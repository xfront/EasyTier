#include <easytier/peer/relay_transport.hpp>
#include <cstdio>
#include <cstring>

namespace easytier {

relay_transport::relay_transport(async_net::io_context& ctx)
    : ctx_(&ctx)
{
}

relay_transport::~relay_transport() {
    close();
}

async_net::Task<bool> relay_transport::connect(const std::string& ip, uint16_t port) {
    sock_ = std::make_unique<async_net::tcp::socket>(*ctx_);
    auto ret = co_await sock_->async_connect(ip.c_str(), port);
    if (ret < 0) {
        std::fprintf(stderr, "[relay] failed to connect to %s:%d\n", ip.c_str(), port);
        sock_.reset();
        co_return false;
    }

    // Set TCP_NODELAY for low latency
    sock_->set_no_delay(true);
    connected_ = true;
    co_return true;
}

async_net::Task<bool> relay_transport::handshake(NodeId my_node_id, VirtualIP my_vip) {
    if (!connected_) co_return false;

    // Send HANDSHAKE
    auto hs = make_handshake_frame(my_node_id, my_vip);
    auto data = hs.serialize();
    size_t written = 0;
    while (written < data.size()) {
        auto n = co_await sock_->async_write_some(
            async_net::const_buffer(data.data() + written, data.size() - written));
        if (n <= 0) co_return false;
        written += static_cast<size_t>(n);
    }

    // Wait for HANDSHAKE_ACK
    auto result = co_await read_frame();
    if (!result || result->type != msg_type::HANDSHAKE_ACK) {
        std::fprintf(stderr, "[relay] expected HANDSHAKE_ACK, got %d\n",
                     result ? static_cast<int>(result->type) : -1);
        co_return false;
    }

    auto hs_ack = payload::handshake_payload::deserialize(
        result->payload.data(), result->payload.size());
    if (!hs_ack) {
        co_return false;
    }

    remote_node_id_ = hs_ack->node_id;
    remote_vip_ = hs_ack->virtual_ip;

    std::fprintf(stderr, "[relay] handshake complete: remote node=%lu VIP=%s\n",
                 (unsigned long)remote_node_id_,
                 virtual_ip_to_string(remote_vip_).c_str());
    co_return true;
}

async_net::Task<std::optional<frame>> relay_transport::read_frame() {
    if (!sock_ || !sock_->is_open()) co_return std::nullopt;

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
        std::fprintf(stderr, "[relay] invalid frame header\n");
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

async_net::Task<bool> relay_transport::send(const frame& f) {
    if (!connected_) co_return false;

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

async_net::Task<std::optional<frame>> relay_transport::receive() {
    co_return co_await read_frame();
}

void relay_transport::close() {
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
    connected_ = false;
}

} // namespace easytier
