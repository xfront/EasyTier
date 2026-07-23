#include <easytier/peer/peer_manager.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace easytier {

peer_manager::peer_manager(async_net::io_context& ctx, const node_config& config,
                           NodeId my_node_id, VirtualIP my_vip)
    : ctx_(&ctx), config_(config), my_node_id_(my_node_id), my_vip_(my_vip)
{
}

peer_manager::~peer_manager() {
    stop();
}

async_net::Task<void> peer_manager::start() {
    running_ = true;

    // Create P2P transport (shared UDP socket)
    uint16_t udp_port = config_.udp_port;
    if (udp_port == 0) udp_port = 12000;  // Default P2P port
    p2p_transport_ = std::make_shared<peer_transport>(*ctx_, udp_port);

    // Create relay TCP acceptor
    uint16_t tcp_port = config_.tcp_port;
    if (tcp_port == 0) tcp_port = 12001;  // Default relay port
    relay_acceptor_ = std::make_unique<async_net::tcp::acceptor>(*ctx_, tcp_port);

    if (!relay_acceptor_->is_open()) {
        std::fprintf(stderr, "[peer-mgr] warning: relay TCP acceptor failed on port %d\n", tcp_port);
    } else {
        std::fprintf(stderr, "[peer-mgr] relay TCP acceptor on port %d\n", tcp_port);
    }

    // Start P2P receive loop
    auto* recv_task = new async_net::Task<void>(p2p_receive_loop());
    {
        std::lock_guard lock(tasks_mutex_);
        active_tasks_.insert(recv_task);
    }
    recv_task->resume();

    // Start relay accept loop
    auto* accept_task = new async_net::Task<void>([&]() -> async_net::Task<void> {
        if (!relay_acceptor_ || !relay_acceptor_->is_open()) co_return;
        while (running_) {
            auto sock = co_await relay_acceptor_->async_accept();
            if (!sock.is_open()) break;

            // Handle incoming relay connection
            auto* relay_task = new async_net::Task<void>([this, s = std::make_shared<async_net::tcp::socket>(std::move(sock))]() -> async_net::Task<void> {
                // Read HANDSHAKE
                uint8_t hdr_buf[FRAME_HEADER_SIZE];
                size_t hdr_read = 0;
                while (hdr_read < FRAME_HEADER_SIZE) {
                    auto n = co_await s->async_read_some(
                        async_net::mutable_buffer(hdr_buf + hdr_read, FRAME_HEADER_SIZE - hdr_read));
                    if (n <= 0) co_return;
                    hdr_read += static_cast<size_t>(n);
                }
                frame_header hdr;
                if (!hdr.deserialize(hdr_buf)) co_return;

                std::vector<uint8_t> payload(hdr.length);
                size_t pr = 0;
                while (pr < hdr.length) {
                    auto n = co_await s->async_read_some(
                        async_net::mutable_buffer(payload.data() + pr, hdr.length - pr));
                    if (n <= 0) co_return;
                    pr += static_cast<size_t>(n);
                }

                auto hs = payload::handshake_payload::deserialize(payload.data(), payload.size());
                if (!hs) co_return;

                // Send HANDSHAKE_ACK
                auto ack = make_handshake_ack_frame(my_node_id_, my_vip_);
                auto ack_data = ack.serialize();
                co_await s->async_write(async_net::const_buffer(ack_data.data(), ack_data.size()));

                // Create peer state for this relay connection
                NodeId remote_nid = hs->node_id;
                VirtualIP remote_vip = hs->virtual_ip;

                {
                    std::lock_guard lock(peers_mutex_);
                    auto& ps = peers_[remote_nid];
                    ps.node_id = remote_nid;
                    ps.virtual_ip = remote_vip;
                    ps.transport = transport_type::relay;
                    ps.state = connection_state::connected;
                    ps.last_seen = std::chrono::steady_clock::now();
                    // Note: the relay socket is stored in a shared_ptr for the receive loop
                }

                std::fprintf(stderr, "[peer-mgr] incoming relay from node %lu (VIP=%s)\n",
                             (unsigned long)remote_nid,
                             virtual_ip_to_string(remote_vip).c_str());

                // Receive loop for this relay connection
                while (running_) {
                    // Read frames from relay
                    uint8_t rbuf[65536 + FRAME_HEADER_SIZE];
                    size_t rh = 0;
                    while (rh < FRAME_HEADER_SIZE) {
                        auto n = co_await s->async_read_some(
                            async_net::mutable_buffer(rbuf + rh, FRAME_HEADER_SIZE - rh));
                        if (n <= 0) co_return;
                        rh += static_cast<size_t>(n);
                    }
                    frame_header rhdr;
                    if (!rhdr.deserialize(rbuf)) co_return;
                    size_t total = FRAME_HEADER_SIZE + rhdr.length;
                    while (rh < total) {
                        auto n = co_await s->async_read_some(
                            async_net::mutable_buffer(rbuf + rh, total - rh));
                        if (n <= 0) co_return;
                        rh += static_cast<size_t>(n);
                    }
                    auto f = frame::deserialize(rbuf, total);
                    if (!f) co_return;

                    if (f->type == msg_type::DATA) {
                        auto dp = payload::data_payload::deserialize(
                            f->payload.data(), f->payload.size());
                        if (dp && data_cb_) {
                            data_cb_(dp->src_node_id, dp->dst_virtual_ip,
                                     dp->ip_packet.data(), dp->ip_packet.size());
                        }
                    }
                }
            }());
            {
                std::lock_guard lock(tasks_mutex_);
                active_tasks_.insert(relay_task);
            }
            relay_task->resume();
        }
    }());
    {
        std::lock_guard lock(tasks_mutex_);
        active_tasks_.insert(accept_task);
    }
    accept_task->resume();

    // Start keepalive loop
    auto* ka_task = new async_net::Task<void>(keepalive_loop());
    {
        std::lock_guard lock(tasks_mutex_);
        active_tasks_.insert(ka_task);
    }
    ka_task->resume();

    std::fprintf(stderr, "[peer-mgr] started (P2P UDP:%d, Relay TCP:%d)\n",
                 udp_port, tcp_port);
    co_return;
}

async_net::Task<void> peer_manager::p2p_receive_loop() {
    while (running_ && p2p_transport_ && p2p_transport_->is_open()) {
        auto result = co_await p2p_transport_->receive();
        if (!result) continue;

        auto& r = *result;

        switch (r.frm.type) {
        case msg_type::PING:
            // Respond with PONG
            co_await p2p_transport_->send_to(make_pong_frame(), r.sender_ip, r.sender_port);
            break;

        case msg_type::PONG: {
            // Update last_seen and latency for the peer at this endpoint
            auto now = std::chrono::steady_clock::now();
            std::lock_guard lock(peers_mutex_);
            for (auto& [nid, ps] : peers_) {
                if (ps.info.public_address == r.sender_ip &&
                    ps.info.udp_port == r.sender_port) {
                    ps.last_seen = now;
                    // Calculate RTT from last ping
                    if (ps.last_ping_sent != std::chrono::steady_clock::time_point{}) {
                        auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now - ps.last_ping_sent).count();
                        if (rtt > 0 && rtt < 30000) {  // Sanity check
                            // Exponential moving average
                            if (ps.latency_ms == 0) {
                                ps.latency_ms = static_cast<uint32_t>(rtt);
                            } else {
                                ps.latency_ms = (ps.latency_ms * 3 + static_cast<uint32_t>(rtt)) / 4;
                            }
                        }
                    }
                    break;
                }
            }
            break;
        }

        case msg_type::DATA: {
            auto dp = payload::data_payload::deserialize(
                r.frm.payload.data(), r.frm.payload.size());
            if (dp && data_cb_) {
                data_cb_(dp->src_node_id, dp->dst_virtual_ip,
                         dp->ip_packet.data(), dp->ip_packet.size());
            }
            break;
        }

        case msg_type::HANDSHAKE: {
            auto hs = payload::handshake_payload::deserialize(
                r.frm.payload.data(), r.frm.payload.size());
            if (hs) {
                // Update peer info
                std::lock_guard lock(peers_mutex_);
                auto it = peers_.find(hs->node_id);
                if (it != peers_.end()) {
                    it->second.state = connection_state::connected;
                    it->second.last_seen = std::chrono::steady_clock::now();
                }
                // Send HANDSHAKE_ACK
                co_await p2p_transport_->send_to(
                    make_handshake_ack_frame(my_node_id_, my_vip_),
                    r.sender_ip, r.sender_port);
            }
            break;
        }

        case msg_type::HANDSHAKE_ACK: {
            auto hs = payload::handshake_payload::deserialize(
                r.frm.payload.data(), r.frm.payload.size());
            if (hs) {
                std::lock_guard lock(peers_mutex_);
                auto it = peers_.find(hs->node_id);
                if (it != peers_.end()) {
                    it->second.state = connection_state::connected;
                    it->second.last_seen = std::chrono::steady_clock::now();
                }
            }
            break;
        }

        default:
            break;
        }
    }
    co_return;
}

async_net::Task<void> peer_manager::keepalive_loop() {
    while (running_) {
        co_await async_net::sleep_for(config_.peer_keepalive_interval, *ctx_);

        std::vector<std::pair<std::string, uint16_t>> ping_targets;
        {
            std::lock_guard lock(peers_mutex_);
            for (auto& [nid, ps] : peers_) {
                if (ps.state == connection_state::connected && ps.transport == transport_type::p2p) {
                    ps.last_ping_sent = std::chrono::steady_clock::now();
                    ps.ping_seq++;
                    ping_targets.emplace_back(ps.info.public_address, ps.info.udp_port);
                }
            }
        }

        for (const auto& [ip, port] : ping_targets) {
            co_await p2p_transport_->send_ping(ip, port);
        }
    }
    co_return;
}

void peer_manager::add_peer(const node_info& info) {
    if (info.node_id == my_node_id_) return;

    std::lock_guard lock(peers_mutex_);
    if (peers_.count(info.node_id)) {
        // Update existing peer info
        peers_[info.node_id].info = info;
        return;
    }

    peer_state ps;
    ps.node_id = info.node_id;
    ps.virtual_ip = info.virtual_ip;
    ps.info = info;
    ps.p2p = p2p_transport_;
    ps.state = connection_state::connecting;
    ps.last_seen = std::chrono::steady_clock::now();
    peers_[info.node_id] = std::move(ps);

    // Start connection attempt in background
    auto* conn_task = new async_net::Task<void>([this, nid = info.node_id]() -> async_net::Task<void> {
        peer_state* ps_ptr = nullptr;
        {
            std::lock_guard lock(peers_mutex_);
            auto it = peers_.find(nid);
            if (it == peers_.end()) co_return;
            ps_ptr = &it->second;
        }

        // Try P2P first
        bool ok = co_await try_p2p_connect(*ps_ptr);
        if (!ok) {
            // Fall back to relay
            ok = co_await try_relay_connect(*ps_ptr);
        }

        if (ok) {
            std::fprintf(stderr, "[peer-mgr] connected to peer %lu via %s\n",
                         (unsigned long)nid,
                         ps_ptr->transport == transport_type::p2p ? "P2P" : "relay");
        } else {
            std::fprintf(stderr, "[peer-mgr] failed to connect to peer %lu\n",
                         (unsigned long)nid);
            std::lock_guard lock(peers_mutex_);
            peers_.erase(nid);
        }
    }());
    {
        std::lock_guard lock(tasks_mutex_);
        active_tasks_.insert(conn_task);
    }
    conn_task->resume();
}

void peer_manager::remove_peer(NodeId node_id) {
    std::lock_guard lock(peers_mutex_);
    peers_.erase(node_id);
    std::fprintf(stderr, "[peer-mgr] removed peer %lu\n", (unsigned long)node_id);
}

async_net::Task<bool> peer_manager::try_p2p_connect(peer_state& ps) {
    if (!p2p_transport_ || !p2p_transport_->is_open()) co_return false;
    if (ps.info.public_address.empty() || ps.info.udp_port == 0) co_return false;

    // Send PING probes (hole punching)
    for (int i = 0; i < 3; ++i) {
        co_await p2p_transport_->send_ping(ps.info.public_address, ps.info.udp_port);
        co_await async_net::sleep_for(std::chrono::milliseconds(500), *ctx_);
    }

    // Send HANDSHAKE
    auto hs = make_handshake_frame(my_node_id_, my_vip_);
    co_await p2p_transport_->send_to(hs, ps.info.public_address, ps.info.udp_port);

    // Wait briefly for HANDSHAKE_ACK (the P2P receive loop will handle it)
    co_await async_net::sleep_for(std::chrono::seconds(2), *ctx_);

    // Check if peer is connected (the receive loop updates state)
    {
        std::lock_guard lock(peers_mutex_);
        auto it = peers_.find(ps.node_id);
        if (it != peers_.end() && it->second.state == connection_state::connected) {
            it->second.transport = transport_type::p2p;
            ps.transport = transport_type::p2p;
            co_return true;
        }
    }

    co_return false;
}

async_net::Task<bool> peer_manager::try_relay_connect(peer_state& ps) {
    if (ps.info.public_address.empty() || ps.info.tcp_port == 0) co_return false;

    auto relay = std::make_unique<relay_transport>(*ctx_);
    bool ok = co_await relay->connect(ps.info.public_address, ps.info.tcp_port);
    if (!ok) co_return false;

    ok = co_await relay->handshake(my_node_id_, my_vip_);
    if (!ok) {
        relay->close();
        co_return false;
    }

    ps.relay = std::move(relay);
    ps.transport = transport_type::relay;
    ps.state = connection_state::connected;
    ps.last_seen = std::chrono::steady_clock::now();

    // Start relay receive loop for this peer
    auto* recv_task = new async_net::Task<void>([this, nid = ps.node_id]() -> async_net::Task<void> {
        while (running_) {
            relay_transport* relay_ptr = nullptr;
            {
                std::lock_guard lock(peers_mutex_);
                auto it = peers_.find(nid);
                if (it == peers_.end() || !it->second.relay) break;
                relay_ptr = it->second.relay.get();
            }

            auto f = co_await relay_ptr->receive();
            if (!f) break;

            if (f->type == msg_type::DATA) {
                auto dp = payload::data_payload::deserialize(
                    f->payload.data(), f->payload.size());
                if (dp && data_cb_) {
                    data_cb_(dp->src_node_id, dp->dst_virtual_ip,
                             dp->ip_packet.data(), dp->ip_packet.size());
                }
            }
        }

        // Peer disconnected
        std::lock_guard lock(peers_mutex_);
        auto it = peers_.find(nid);
        if (it != peers_.end()) {
            it->second.state = connection_state::disconnected;
        }
    }());
    {
        std::lock_guard lock(tasks_mutex_);
        active_tasks_.insert(recv_task);
    }
    recv_task->resume();

    co_return true;
}

async_net::Task<bool> peer_manager::send_to_virtual_ip(VirtualIP dst_vip,
                                                         const uint8_t* data, size_t len) {
    peer_state* ps = nullptr;
    {
        std::lock_guard lock(peers_mutex_);
        ps = find_peer_by_vip(dst_vip);
        if (!ps) {
            // No route to this virtual IP
            co_return false;
        }
    }

    // Build DATA frame
    auto f = make_data_frame(my_node_id_, dst_vip, data, len);

    if (ps->transport == transport_type::p2p && ps->state == connection_state::connected) {
        // Send via P2P (UDP)
        co_return co_await p2p_transport_->send_to(
            f, ps->info.public_address, ps->info.udp_port);
    } else if (ps->transport == transport_type::relay && ps->relay) {
        // Send via relay (TCP)
        co_return co_await ps->relay->send(f);
    }

    co_return false;
}

async_net::Task<bool> peer_manager::send_to_peer(NodeId node_id, const frame& f) {
    std::lock_guard lock(peers_mutex_);
    auto it = peers_.find(node_id);
    if (it == peers_.end()) co_return false;

    auto& ps = it->second;
    if (ps.transport == transport_type::p2p && ps.state == connection_state::connected) {
        co_return co_await p2p_transport_->send_to(
            f, ps.info.public_address, ps.info.udp_port);
    } else if (ps.transport == transport_type::relay && ps.relay) {
        co_return co_await ps.relay->send(f);
    }

    co_return false;
}

peer_state* peer_manager::find_peer_by_vip(VirtualIP vip) {
    for (auto& [nid, ps] : peers_) {
        if (ps.virtual_ip == vip && ps.state == connection_state::connected) {
            return &ps;
        }
    }
    return nullptr;
}

void peer_manager::set_data_callback(data_callback cb) {
    data_cb_ = std::move(cb);
}

std::vector<node_info> peer_manager::connected_peers() const {
    std::lock_guard lock(peers_mutex_);
    std::vector<node_info> result;
    for (const auto& [nid, ps] : peers_) {
        if (ps.state == connection_state::connected) {
            result.push_back(ps.info);
        }
    }
    return result;
}

uint32_t peer_manager::get_peer_latency(NodeId node_id) const {
    std::lock_guard lock(const_cast<std::mutex&>(peers_mutex_));
    auto it = peers_.find(node_id);
    if (it != peers_.end()) {
        return it->second.latency_ms;
    }
    return 0;
}

std::map<NodeId, uint32_t> peer_manager::all_peer_latencies() const {
    std::lock_guard lock(const_cast<std::mutex&>(peers_mutex_));
    std::map<NodeId, uint32_t> result;
    for (const auto& [nid, ps] : peers_) {
        if (ps.state == connection_state::connected) {
            result[nid] = ps.latency_ms;
        }
    }
    return result;
}

void peer_manager::stop() {
    running_ = false;
    if (p2p_transport_) {
        p2p_transport_->close();
    }
    if (relay_acceptor_) {
        relay_acceptor_->close();
    }
    {
        std::lock_guard lock(peers_mutex_);
        for (auto& [nid, ps] : peers_) {
            if (ps.relay) {
                ps.relay->close();
            }
        }
        peers_.clear();
    }
}

} // namespace easytier
