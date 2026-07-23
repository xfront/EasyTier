#include <easytier/registry/registry_server.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace easytier {

registry_server::registry_server(async_net::io_context& ctx, const registry_config& config)
    : ctx_(&ctx), config_(config)
{
}

registry_server::~registry_server() {
    stop();
}

async_net::Task<void> registry_server::run() {
    acceptor_ = std::make_unique<async_net::tcp::acceptor>(*ctx_, config_.port);
    if (!acceptor_->is_open()) {
        std::fprintf(stderr, "[registry] failed to bind port %d\n", config_.port);
        co_return;
    }

    running_ = true;
    std::fprintf(stderr, "[registry] listening on port %d, network %s/%d\n",
                 config_.port, config_.network_cidr.c_str(), config_.network_mask);

    // Start cleanup timer as a separate coroutine
    auto* cleanup_task = new async_net::Task<void>([&]() -> async_net::Task<void> {
        while (running_) {
            co_await async_net::sleep_for(std::chrono::seconds(30), *ctx_);
            cleanup_stale_nodes();
        }
    }());
    {
        std::lock_guard lock(tasks_mutex_);
        active_tasks_.insert(cleanup_task);
    }
    cleanup_task->resume();

    while (running_) {
        auto sock = co_await acceptor_->async_accept();
        if (!sock.is_open()) break;

        auto* task = new async_net::Task<void>(handle_client(std::move(sock)));
        {
            std::lock_guard lock(tasks_mutex_);
            active_tasks_.insert(task);
        }
        task->resume();
    }

    co_return;
}

async_net::Task<std::optional<frame>> registry_server::read_frame(async_net::tcp::socket& sock) {
    // Read header first (8 bytes)
    uint8_t hdr_buf[FRAME_HEADER_SIZE];
    size_t hdr_read = 0;
    while (hdr_read < FRAME_HEADER_SIZE) {
        auto n = co_await sock.async_read_some(
            async_net::mutable_buffer(hdr_buf + hdr_read, FRAME_HEADER_SIZE - hdr_read));
        if (n <= 0) co_return std::nullopt;
        hdr_read += static_cast<size_t>(n);
    }

    frame_header hdr;
    if (!hdr.deserialize(hdr_buf)) {
        std::fprintf(stderr, "[registry] invalid frame header\n");
        co_return std::nullopt;
    }

    // Read payload
    std::vector<uint8_t> payload(hdr.length);
    size_t payload_read = 0;
    while (payload_read < hdr.length) {
        auto n = co_await sock.async_read_some(
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

async_net::Task<bool> registry_server::write_frame(async_net::tcp::socket& sock, const frame& f) {
    auto data = f.serialize();
    size_t written = 0;
    while (written < data.size()) {
        auto n = co_await sock.async_write_some(
            async_net::const_buffer(data.data() + written, data.size() - written));
        if (n <= 0) co_return false;
        written += static_cast<size_t>(n);
    }
    co_return true;
}

async_net::Task<void> registry_server::handle_client(async_net::tcp::socket sock) {
    int fd = sock.native_handle();
    NodeId my_node_id = 0;
    bool registered = false;

    // Store the socket for push notifications
    auto sock_ptr = std::make_shared<async_net::tcp::socket>(std::move(sock));
    {
        std::lock_guard lock(fd_mutex_);
        client_sockets_[fd] = sock_ptr;
    }

    while (running_) {
        auto result = co_await read_frame(*sock_ptr);
        if (!result.has_value()) break;

        const auto& f = result.value();

        switch (f.type) {
        case msg_type::REGISTER: {
            auto p = payload::register_payload::deserialize(f.payload.data(), f.payload.size());
            if (!p) break;

            my_node_id = p->node_id;
            VirtualIP vip = allocate_virtual_ip();

            // Register the node
            {
                std::lock_guard lock(nodes_mutex_);
                connected_node cn;
                cn.info.node_id = my_node_id;
                cn.info.virtual_ip = vip;
                cn.info.public_address = "";  // Will be filled from socket
                cn.info.udp_port = p->udp_port;
                cn.info.tcp_port = p->tcp_port;
                cn.info.name = p->name;
                cn.virtual_ip = vip;
                cn.last_seen = std::chrono::steady_clock::now();
                cn.socket_fd = fd;
                nodes_[my_node_id] = cn;
            }
            {
                std::lock_guard lock(fd_mutex_);
                fd_to_node_[fd] = my_node_id;
            }

            registered = true;

            // Send REGISTER_ACK
            auto ack = make_register_ack_frame(my_node_id, vip);
            co_await write_frame(*sock_ptr, ack);

            // Send current node list
            std::vector<payload::node_entry> entries;
            {
                std::lock_guard lock(nodes_mutex_);
                for (const auto& [nid, cn] : nodes_) {
                    if (nid == my_node_id) continue;
                    payload::node_entry e;
                    e.node_id = cn.info.node_id;
                    e.virtual_ip = cn.virtual_ip;
                    e.public_address = cn.info.public_address;
                    e.udp_port = cn.info.udp_port;
                    e.tcp_port = cn.info.tcp_port;
                    e.name = cn.info.name;
                    entries.push_back(std::move(e));
                }
            }
            payload::node_list_payload nlp;
            nlp.nodes = std::move(entries);
            frame list_frame{msg_type::NODE_LIST, nlp.serialize()};
            co_await write_frame(*sock_ptr, list_frame);

            // Notify other clients about the new node
            notify_node_joined(my_node_id, vip, "", p->udp_port, p->tcp_port, p->name);

            std::fprintf(stderr, "[registry] node %lu registered, VIP=%s, name=%s\n",
                         (unsigned long)my_node_id,
                         virtual_ip_to_string(vip).c_str(), p->name.c_str());
            break;
        }

        case msg_type::LIST_NODES: {
            std::vector<payload::node_entry> entries;
            {
                std::lock_guard lock(nodes_mutex_);
                for (const auto& [nid, cn] : nodes_) {
                    if (nid == my_node_id) continue;
                    payload::node_entry e;
                    e.node_id = cn.info.node_id;
                    e.virtual_ip = cn.virtual_ip;
                    e.public_address = cn.info.public_address;
                    e.udp_port = cn.info.udp_port;
                    e.tcp_port = cn.info.tcp_port;
                    e.name = cn.info.name;
                    entries.push_back(std::move(e));
                }
            }
            payload::node_list_payload nlp;
            nlp.nodes = std::move(entries);
            frame list_frame{msg_type::NODE_LIST, nlp.serialize()};
            co_await write_frame(*sock_ptr, list_frame);
            break;
        }

        case msg_type::HEARTBEAT: {
            // Update last_seen
            {
                std::lock_guard lock(nodes_mutex_);
                auto it = nodes_.find(my_node_id);
                if (it != nodes_.end()) {
                    it->second.last_seen = std::chrono::steady_clock::now();
                }
            }
            // Send HEARTBEAT_ACK
            auto ack = make_heartbeat_ack_frame();
            co_await write_frame(*sock_ptr, ack);
            break;
        }

        default:
            std::fprintf(stderr, "[registry] unexpected message type %d from node %lu\n",
                         static_cast<int>(f.type), (unsigned long)my_node_id);
            break;
        }
    }

    // Client disconnected
    if (registered && my_node_id != 0) {
        {
            std::lock_guard lock(nodes_mutex_);
            nodes_.erase(my_node_id);
        }
        {
            std::lock_guard lock(fd_mutex_);
            fd_to_node_.erase(fd);
            client_sockets_.erase(fd);
        }
        notify_node_left(my_node_id);
        std::fprintf(stderr, "[registry] node %lu disconnected\n", (unsigned long)my_node_id);
    }

    // Remove this task from active set
    // (Task will be cleaned up when the coroutine frame is destroyed)
}

VirtualIP registry_server::allocate_virtual_ip() {
    // Parse the base network address
    VirtualIP base_ip = string_to_virtual_ip(config_.network_cidr);
    auto* bytes = reinterpret_cast<uint8_t*>(&base_ip);

    // Calculate the number of host bits
    int host_bits = 32 - config_.network_mask;
    uint32_t max_hosts = (1U << host_bits) - 2;  // Exclude network and broadcast

    // Find next available IP
    while (next_ip_suffix_ <= max_hosts) {
        uint32_t suffix = next_ip_suffix_++;

        // Set the host part of the IP
        VirtualIP new_ip = base_ip;
        auto* new_bytes = reinterpret_cast<uint8_t*>(&new_ip);

        if (host_bits <= 8) {
            new_bytes[3] = static_cast<uint8_t>(suffix);
        } else if (host_bits <= 16) {
            new_bytes[2] = static_cast<uint8_t>((suffix >> 8) & 0xFF);
            new_bytes[3] = static_cast<uint8_t>(suffix & 0xFF);
        } else {
            new_bytes[1] = static_cast<uint8_t>((suffix >> 16) & 0xFF);
            new_bytes[2] = static_cast<uint8_t>((suffix >> 8) & 0xFF);
            new_bytes[3] = static_cast<uint8_t>(suffix & 0xFF);
        }

        // Check if already in use
        bool in_use = false;
        {
            std::lock_guard lock(nodes_mutex_);
            for (const auto& [nid, cn] : nodes_) {
                if (cn.virtual_ip == new_ip) {
                    in_use = true;
                    break;
                }
            }
        }
        if (!in_use) return new_ip;
    }

    // No more IPs available
    std::fprintf(stderr, "[registry] WARNING: virtual IP pool exhausted!\n");
    return 0;
}

void registry_server::cleanup_stale_nodes() {
    auto now = std::chrono::steady_clock::now();
    std::vector<NodeId> stale;

    {
        std::lock_guard lock(nodes_mutex_);
        for (const auto& [nid, cn] : nodes_) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - cn.last_seen).count();
            if (elapsed > config_.peer_timeout.count()) {
                stale.push_back(nid);
            }
        }
    }

    for (auto nid : stale) {
        {
            std::lock_guard lock(nodes_mutex_);
            auto it = nodes_.find(nid);
            if (it != nodes_.end()) {
                int fd = it->second.socket_fd;
                {
                    std::lock_guard fd_lock(fd_mutex_);
                    fd_to_node_.erase(fd);
                    client_sockets_.erase(fd);
                }
                nodes_.erase(it);
            }
        }
        notify_node_left(nid);
        std::fprintf(stderr, "[registry] node %lu timed out, removed\n", (unsigned long)nid);
    }

    if (!stale.empty()) {
        std::lock_guard lock(nodes_mutex_);
        std::fprintf(stderr, "[registry] %zu nodes online\n", nodes_.size());
    }
}

void registry_server::notify_node_joined(NodeId node_id, VirtualIP vip,
                                          const std::string& addr, uint16_t udp_port,
                                          uint16_t tcp_port, const std::string& name) {
    // Build NODE_JOINED frame
    payload::node_entry e;
    e.node_id = node_id;
    e.virtual_ip = vip;
    e.public_address = addr;
    e.udp_port = udp_port;
    e.tcp_port = tcp_port;
    e.name = name;

    // Serialize single node entry as payload
    std::vector<uint8_t> payload_buf(e.serialized_size());
    e.serialize_to(payload_buf.data());

    frame f{msg_type::NODE_JOINED, std::move(payload_buf)};

    // Send to all connected clients except the new node
    std::lock_guard lock(fd_mutex_);
    for (auto& [fd, sock_ptr] : client_sockets_) {
        NodeId nid = 0;
        {
            auto it = fd_to_node_.find(fd);
            if (it != fd_to_node_.end()) nid = it->second;
        }
        if (nid != node_id) {
            // Fire-and-forget write (best effort)
            auto data = f.serialize();
            auto sock_copy = sock_ptr;
            ctx_->post([sock_copy, data]() {
                // Best-effort async write (non-blocking)
                auto n = ::send(sock_copy->native_handle(),
                                data.data(), data.size(), MSG_DONTWAIT);
                (void)n;
            });
        }
    }
}

void registry_server::notify_node_left(NodeId node_id) {
    // Build NODE_LEFT frame with the node_id (4 bytes, big-endian)
    std::vector<uint8_t> payload_buf(4);
    payload_buf[0] = static_cast<uint8_t>((node_id >> 24) & 0xFF);
    payload_buf[1] = static_cast<uint8_t>((node_id >> 16) & 0xFF);
    payload_buf[2] = static_cast<uint8_t>((node_id >> 8) & 0xFF);
    payload_buf[3] = static_cast<uint8_t>(node_id & 0xFF);

    frame f{msg_type::NODE_LEFT, std::move(payload_buf)};

    std::lock_guard lock(fd_mutex_);
    for (auto& [fd, sock_ptr] : client_sockets_) {
        auto data = f.serialize();
        auto sock_copy = sock_ptr;
        ctx_->post([sock_copy, data]() {
            auto n = ::send(sock_copy->native_handle(),
                            data.data(), data.size(), MSG_DONTWAIT);
            (void)n;
        });
    }
}

void registry_server::send_to_client(int fd, const frame& f) {
    std::lock_guard lock(fd_mutex_);
    auto it = client_sockets_.find(fd);
    if (it == client_sockets_.end()) return;

    auto data = f.serialize();
    auto sock_copy = it->second;
    ctx_->post([sock_copy, data]() {
        auto n = ::send(sock_copy->native_handle(),
                        data.data(), data.size(), MSG_DONTWAIT);
        (void)n;
    });
}

std::vector<node_info> registry_server::nodes() const {
    std::lock_guard lock(nodes_mutex_);
    std::vector<node_info> result;
    result.reserve(nodes_.size());
    for (const auto& [nid, cn] : nodes_) {
        result.push_back(cn.info);
    }
    return result;
}

void registry_server::stop() {
    running_ = false;
    if (acceptor_) {
        acceptor_->close();
    }
}

} // namespace easytier
