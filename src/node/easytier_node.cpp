#include <easytier/node/easytier_node.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstdio>

namespace easytier {

easytier_node::easytier_node(async_net::io_context& ctx, const node_config& config)
    : ctx_(&ctx), config_(config)
{
    // Auto-generate node ID if not set
    if (config_.my_peer_id == 0) {
        config_.my_peer_id = generate_node_id();
    }
}

easytier_node::~easytier_node() {
    stop();
}

async_net::Task<void> easytier_node::run() {
    running_ = true;

    std::fprintf(stderr, "[node] starting EasyTier node '%s' (id=%u)\n",
                 config_.name.c_str(), config_.my_peer_id);

    // Step 1: Connect to registry OR bootstrap DHT
    if (config_.enable_dht && !config_.bootstrap_nodes.empty()) {
        // DHT mode: decentralized
        std::fprintf(stderr, "[node] DHT mode: bootstrapping from %zu nodes\n",
                     config_.bootstrap_nodes.size());

        // TODO: Implement DHT bootstrap and VIP assignment
        // For now, fall back to registry mode
        std::fprintf(stderr, "[node] DHT mode not fully implemented, falling back to registry\n");
    }

    // Registry mode (default) — uses Rust-compatible protocol
    registry_ = std::make_unique<registry_client>(*ctx_);
    registry_->set_network_identity(config_.network_name, config_.network_secret);
    bool ok = co_await registry_->connect(
        config_.registry_host.c_str(), config_.registry_port,
        config_.my_peer_id, config_.udp_port, config_.tcp_port, config_.name);

    if (!ok) {
        std::fprintf(stderr, "[node] failed to connect to server at %s:%d\n",
                     config_.registry_host.c_str(), config_.registry_port);
        running_ = false;
        co_return;
    }

    virtual_ip_ = registry_->virtual_ip();
    config_.my_peer_id = registry_->node_id();

    // If no VIP assigned by server, derive from peer_id
    if (virtual_ip_ == 0) {
        uint32_t pid = config_.my_peer_id;
        // virtual_ip_to_string reads memory bytes directly (little-endian on x86)
        // So for "10.a.b.c", memory must be [0x0A, a, b, c]
        // uint32_t value (LE) = (c << 24) | (b << 16) | (a << 8) | 0x0A
        uint8_t a = (pid >> 8) & 0xFF;
        uint8_t b = (pid >> 16) & 0xFF;
        uint8_t c = (pid >> 24) & 0xFF;
        virtual_ip_ = (static_cast<VirtualIP>(c) << 24)
                    | (static_cast<VirtualIP>(b) << 16)
                    | (static_cast<VirtualIP>(a) << 8)
                    | 10;
        std::fprintf(stderr, "[node] derived VIP %s from peer_id %u\n",
                     virtual_ip_to_string(virtual_ip_).c_str(), config_.my_peer_id);
    }

    std::fprintf(stderr, "[node] handshake complete: peer_id=%u, server_peer_id=%u, vip=%s\n",
                 config_.my_peer_id, registry_->server_peer_id(),
                 virtual_ip_to_string(virtual_ip_).c_str());

    // Step 2: Create TUN device
    tun_ = std::make_unique<tun_device>(
        *ctx_, config_.tun_name, virtual_ip_to_string(virtual_ip_),
        config_.network_mask, config_.mtu);

    if (!tun_->is_open()) {
        std::fprintf(stderr, "[node] failed to create TUN device\n");
        running_ = false;
        co_return;
    }

    std::fprintf(stderr, "[node] TUN device '%s' created with IP %s\n",
                 tun_->name().c_str(), tun_->ip_address().c_str());

    // Step 3: Start peer manager
    peer_mgr_ = std::make_unique<peer_manager>(*ctx_, config_, config_.my_peer_id, virtual_ip_);
    auto* pm_task = new async_net::Task<void>(peer_mgr_->start());
    pm_task->resume();

    // Step 4: Start router (with smart routing)
    router_ = std::make_unique<router>(*ctx_, *tun_, *peer_mgr_);
    auto* router_task = new async_net::Task<void>(router_->start());
    router_task->resume();

    // Step 5: Start subnet proxy
    subnet_proxy_ = std::make_unique<subnet_proxy>();
    for (const auto& subnet : config_.proxy_subnets) {
        subnet_proxy_->announce_subnet(subnet, config_.my_peer_id, virtual_ip_);
    }

    // Step 6: Start web API (if enabled)
    if (config_.enable_web_api && config_.web_api_port > 0) {
        web_ = std::make_unique<web_api>(*ctx_, config_.web_api_port);
        auto* web_task = new async_net::Task<void>(web_->start());
        web_task->resume();
        std::fprintf(stderr, "[node] Web API listening on port %d\n", config_.web_api_port);
    }

    // Step 7: Start heartbeat and notification loops
    auto* hb_task = new async_net::Task<void>(heartbeat_loop());
    hb_task->resume();

    auto* notif_task = new async_net::Task<void>(registry_notification_loop());
    notif_task->resume();

    auto* status_task = new async_net::Task<void>(status_loop());
    status_task->resume();

    std::fprintf(stderr, "[node] EasyTier node is running\n");
    std::fprintf(stderr, "[node] Virtual IP: %s\n", virtual_ip_to_string(virtual_ip_).c_str());
    std::fprintf(stderr, "[node] TUN device: %s\n", tun_->name().c_str());
    if (!config_.proxy_subnets.empty()) {
        std::fprintf(stderr, "[node] Proxying %zu subnets\n", config_.proxy_subnets.size());
    }

    // Keep running until stopped
    while (running_.load()) {
        co_await async_net::sleep_for(std::chrono::seconds(1), *ctx_);
    }

    co_return;
}

async_net::Task<void> easytier_node::registry_notification_loop() {
    while (running_ && registry_ && registry_->is_connected()) {
        auto result = co_await registry_->read_notification();
        if (!result) {
            std::fprintf(stderr, "[node] registry connection lost\n");
            break;
        }

        const auto& f = *result;

        switch (f.type) {
        case msg_type::NODE_JOINED: {
            auto entry = payload::node_entry::deserialize_from(
                f.payload.data(), f.payload.size());
            if (entry) {
                node_info ni;
                ni.node_id = entry->node_id;
                ni.virtual_ip = entry->virtual_ip;
                ni.public_address = entry->public_address;
                ni.udp_port = entry->udp_port;
                ni.tcp_port = entry->tcp_port;
                ni.name = entry->name;

                std::fprintf(stderr, "[node] peer joined: %s (VIP=%s)\n",
                             ni.name.c_str(),
                             virtual_ip_to_string(ni.virtual_ip).c_str());

                if (peer_mgr_) {
                    peer_mgr_->add_peer(ni);
                }
            }
            break;
        }

        case msg_type::NODE_LEFT: {
            if (f.payload.size() >= 4) {
                NodeId nid = 0;
                for (int i = 0; i < 4; ++i) {
                    nid = (nid << 8) | f.payload[i];
                }
                std::fprintf(stderr, "[node] peer left: node %u\n", nid);

                if (peer_mgr_) {
                    peer_mgr_->remove_peer(nid);
                }
            }
            break;
        }

        case msg_type::ROUTE_UPDATE: {
            // Handle route updates from peers
            auto update = payload::route_update_payload::deserialize(
                f.payload.data(), f.payload.size());
            if (update && router_) {
                std::vector<route_entry> entries;
                for (const auto& e : update->entries) {
                    route_entry re;
                    re.dst_vip = e.dst_vip;
                    re.via_node = e.via_node;
                    re.latency_ms = e.latency_ms;
                    re.hop_count = e.hop_count;
                    entries.push_back(re);
                }
                // Find which peer sent this
                // For now, use the first connected peer
                auto peers = peer_mgr_ ? peer_mgr_->connected_peers() : std::vector<node_info>{};
                if (!peers.empty()) {
                    router_->update_routes(peers[0].node_id, entries);
                }
            }
            break;
        }

        case msg_type::HEARTBEAT_ACK:
            // Ignore (handled by heartbeat_loop)
            break;

        default:
            break;
        }
    }
    co_return;
}

async_net::Task<void> easytier_node::heartbeat_loop() {
    while (running_ && registry_ && registry_->is_connected()) {
        co_await async_net::sleep_for(config_.registry_heartbeat_interval, *ctx_);
        if (!running_) break;

        bool ok = co_await registry_->heartbeat();
        if (!ok) {
            std::fprintf(stderr, "[node] heartbeat failed, registry may be down\n");
        }
    }
    co_return;
}

async_net::Task<void> easytier_node::status_loop() {
    while (running_) {
        co_await async_net::sleep_for(std::chrono::seconds(30), *ctx_);
        if (!running_) break;

        auto peers = peer_mgr_ ? peer_mgr_->connected_peers() : std::vector<node_info>{};
        auto t2n = router_ ? router_->tun_to_net_packets() : 0;
        auto n2t = router_ ? router_->net_to_tun_packets() : 0;
        auto routes = router_ ? router_->get_routes() : std::vector<route_entry>{};

        std::fprintf(stderr, "[node] status: %zu peers, %zu routes, TUN->NET=%lu pkts, NET->TUN=%lu pkts\n",
                     peers.size(), routes.size(), (unsigned long)t2n, (unsigned long)n2t);

        // Log peer latencies
        if (peer_mgr_ && !peers.empty()) {
            auto latencies = peer_mgr_->all_peer_latencies();
            for (const auto& [nid, lat] : latencies) {
                std::fprintf(stderr, "[node]   peer %u: %u ms\n", nid, lat);
            }
        }
    }
    co_return;
}

void easytier_node::stop() {
    if (!running_.exchange(false)) return;

    std::fprintf(stderr, "[node] stopping...\n");

    if (web_) web_->stop();
    if (router_) router_->stop();
    if (peer_mgr_) peer_mgr_->stop();
    if (registry_) {
        // Synchronous disconnect (best effort)
        registry_->disconnect();
    }
    if (tun_) tun_->close();
}

} // namespace easytier
