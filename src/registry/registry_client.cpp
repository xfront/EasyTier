#include <easytier/registry/registry_client.hpp>
#include <cstdio>
#include <cstring>

namespace easytier {

registry_client::registry_client(async_net::io_context& ctx)
    : ctx_(&ctx)
{
}

registry_client::~registry_client() {
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
}

async_net::Task<std::optional<frame>> registry_client::read_frame() {
    // Read header (8 bytes)
    uint8_t hdr_buf[FRAME_HEADER_SIZE];
    size_t hdr_read = 0;
    while (hdr_read < FRAME_HEADER_SIZE) {
        auto n = co_await sock_->async_read_some(
            async_net::mutable_buffer(hdr_buf + hdr_read, FRAME_HEADER_SIZE - hdr_read));
        if (n <= 0) co_return std::nullopt;
        hdr_read += static_cast<size_t>(n);
    }

    frame_header hdr;
    if (!hdr.deserialize(hdr_buf)) {
        std::fprintf(stderr, "[reg-client] invalid frame header\n");
        co_return std::nullopt;
    }

    // Read payload
    std::vector<uint8_t> payload(hdr.length);
    size_t payload_read = 0;
    while (payload_read < hdr.length) {
        auto n = co_await sock_->async_read_some(
            async_net::mutable_buffer(payload.data() + payload_read,
                                       hdr.length - payload_read));
        if (n <= 0) co_return std::nullopt;
        payload_read += static_cast<size_t>(n);
    }

    frame f;
    f.type = static_cast<msg_type>(hdr.type);
    f.payload = std::move(payload);
    co_return f;
}

async_net::Task<bool> registry_client::write_frame(const frame& f) {
    auto data = f.serialize();
    size_t written = 0;
    while (written < data.size()) {
        auto n = co_await sock_->async_write_some(
            async_net::const_buffer(data.data() + written, data.size() - written));
        if (n <= 0) co_return false;
        written += static_cast<size_t>(n);
    }
    co_return true;
}

async_net::Task<bool> registry_client::connect(const char* host, uint16_t port,
                                                 NodeId node_id, uint16_t udp_port,
                                                 uint16_t tcp_port, const std::string& name) {
    sock_ = std::make_unique<async_net::tcp::socket>(*ctx_);
    auto ret = co_await sock_->async_connect(host, port);
    if (ret < 0) {
        std::fprintf(stderr, "[reg-client] failed to connect to %s:%d\n", host, port);
        co_return false;
    }

    node_id_ = node_id;

    // Send REGISTER
    auto reg = make_register_frame(node_id, udp_port, tcp_port, name);
    if (!co_await write_frame(reg)) {
        std::fprintf(stderr, "[reg-client] failed to send REGISTER\n");
        co_return false;
    }

    // Wait for REGISTER_ACK
    auto result = co_await read_frame();
    if (!result || result->type != msg_type::REGISTER_ACK) {
        std::fprintf(stderr, "[reg-client] expected REGISTER_ACK, got %d\n",
                     result ? static_cast<int>(result->type) : -1);
        co_return false;
    }

    auto ack = payload::register_ack_payload::deserialize(
        result->payload.data(), result->payload.size());
    if (!ack) {
        std::fprintf(stderr, "[reg-client] invalid REGISTER_ACK payload\n");
        co_return false;
    }

    node_id_ = ack->node_id;
    virtual_ip_ = ack->virtual_ip;

    // Read the initial node list
    result = co_await read_frame();
    if (result && result->type == msg_type::NODE_LIST) {
        // Parse and store the initial node list (caller will use list_nodes() for updates)
        auto nlp = payload::node_list_payload::deserialize(
            result->payload.data(), result->payload.size());
        if (nlp) {
            std::fprintf(stderr, "[reg-client] %zu nodes currently online\n", nlp->nodes.size());
        }
    }

    connected_ = true;
    std::fprintf(stderr, "[reg-client] registered: node_id=%lu, virtual_ip=%s\n",
                 (unsigned long)node_id_,
                 virtual_ip_to_string(virtual_ip_).c_str());
    co_return true;
}

async_net::Task<std::vector<node_info>> registry_client::list_nodes() {
    auto req = make_list_nodes_frame();
    if (!co_await write_frame(req)) {
        co_return std::vector<node_info>{};
    }

    auto result = co_await read_frame();
    if (!result || result->type != msg_type::NODE_LIST) {
        co_return std::vector<node_info>{};
    }

    auto nlp = payload::node_list_payload::deserialize(
        result->payload.data(), result->payload.size());
    if (!nlp) {
        co_return std::vector<node_info>{};
    }

    std::vector<node_info> nodes;
    for (const auto& e : nlp->nodes) {
        node_info ni;
        ni.node_id = e.node_id;
        ni.virtual_ip = e.virtual_ip;
        ni.public_address = e.public_address;
        ni.udp_port = e.udp_port;
        ni.tcp_port = e.tcp_port;
        ni.name = e.name;
        nodes.push_back(std::move(ni));
    }
    co_return nodes;
}

async_net::Task<bool> registry_client::heartbeat() {
    auto hb = make_heartbeat_frame();
    if (!co_await write_frame(hb)) {
        co_return false;
    }

    auto result = co_await read_frame();
    if (!result || result->type != msg_type::HEARTBEAT_ACK) {
        co_return false;
    }
    co_return true;
}

async_net::Task<std::optional<frame>> registry_client::read_notification() {
    co_return co_await read_frame();
}

async_net::Task<void> registry_client::disconnect() {
    if (sock_ && sock_->is_open()) {
        auto disc = make_disconnect_frame();
        co_await write_frame(disc);
        sock_->close();
    }
    connected_ = false;
    co_return;
}

} // namespace easytier
