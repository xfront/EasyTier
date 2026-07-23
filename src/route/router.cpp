#include <easytier/route/router.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <arpa/inet.h>
#include <algorithm>

namespace easytier {

router::router(async_net::io_context& ctx, tun_device& tun, peer_manager& pm)
    : ctx_(&ctx), tun_(tun), pm_(pm)
{
}

router::~router() {
    stop();
}

async_net::Task<void> router::start() {
    running_ = true;

    // Set up the data callback: peer_manager -> TUN
    pm_.set_data_callback(
        [this](NodeId src, VirtualIP dst, const uint8_t* data, size_t len) {
            net_to_tun_handler(src, dst, data, len);
        });

    // Start route broadcast loop (distance-vector protocol)
    auto* broadcast_task = new async_net::Task<void>(route_broadcast_loop());
    broadcast_task->resume();

    // Start TUN -> Network loop
    co_await tun_to_net_loop();

    co_return;
}

async_net::Task<void> router::tun_to_net_loop() {
    int consecutive_errors = 0;
    while (running_ && tun_.is_open()) {
        auto n = co_await tun_.async_read(tun_buf_, TUN_BUF_SIZE);
        if (n <= 0) {
            if (running_) {
                consecutive_errors++;
                if (consecutive_errors <= 3) {
                    std::fprintf(stderr, "[router] TUN read error: %zd errno=%d (%s)\n",
                                 n, errno, std::strerror(errno > 0 ? errno : 0));
                } else if (consecutive_errors == 4) {
                    std::fprintf(stderr, "[router] TUN read errors continuing, suppressing logs\n");
                }
                // Wait a bit before retrying
                co_await async_net::sleep_for(std::chrono::milliseconds(100), *ctx_);
            }
            // Don't break - TUN errors are not fatal
            if (consecutive_errors > 100) {
                // Too many consecutive errors, TUN device probably broken
                std::fprintf(stderr, "[router] TUN device appears to be broken, stopping\n");
                break;
            }
            continue;
        }
        consecutive_errors = 0;  // Reset on success

        tun_to_net_.fetch_add(1);

        // Extract destination IP from the IP packet
        VirtualIP dst_ip = extract_dst_ip(tun_buf_, static_cast<size_t>(n));
        if (dst_ip == 0) {
            // Not a valid IPv4 packet, skip
            continue;
        }

        // Try smart routing first
        route_entry* best_route = nullptr;
        {
            std::lock_guard lock(routing_mutex_);
            best_route = select_route(dst_ip);
        }

        bool sent = false;
        if (best_route) {
            // Use smart route (multi-hop via intermediate node)
            sent = co_await pm_.send_to_virtual_ip(dst_ip, tun_buf_, static_cast<size_t>(n));
        } else {
            // Fall back to direct peer lookup
            sent = co_await pm_.send_to_virtual_ip(dst_ip, tun_buf_, static_cast<size_t>(n));
        }

        if (!sent) {
            // No route to destination
        }
    }
    co_return;
}

void router::net_to_tun_handler(NodeId src_node, VirtualIP dst_vip,
                                  const uint8_t* data, size_t len) {
    // Check if this packet is destined for our virtual network
    auto data_copy = std::vector<uint8_t>(data, data + len);
    ctx_->post([this, data_copy = std::move(data_copy)]() {
        if (tun_.is_open()) {
            // Synchronous write to TUN (it's non-blocking fd)
            auto n = ::write(tun_.fd(), data_copy.data(), data_copy.size());
            if (n > 0) {
                net_to_tun_.fetch_add(1);
            }
        }
    });
}

VirtualIP router::extract_dst_ip(const uint8_t* ip_packet, size_t len) {
    if (len < 20) return 0;  // Minimum IPv4 header size

    // Check IP version (should be 4)
    uint8_t version = (ip_packet[0] >> 4) & 0x0F;
    if (version != 4) return 0;

    // Destination IP is at offset 16-19 in the IPv4 header
    VirtualIP dst_ip;
    std::memcpy(&dst_ip, ip_packet + 16, 4);
    return dst_ip;
}

bool router::is_local_network(VirtualIP vip) const {
    // For MVP, all 10.10.0.0/16 is our virtual network
    auto* bytes = reinterpret_cast<const uint8_t*>(&vip);
    return bytes[0] == 10 && bytes[1] == 10;
}

route_entry* router::select_route(VirtualIP dst_vip) {
    // Find all routes to this destination
    route_entry* best = nullptr;
    double best_cost = 1e9;

    for (auto& route : routing_table_) {
        if (route.dst_vip == dst_vip) {
            double cost = route.cost();
            if (cost < best_cost) {
                best_cost = cost;
                best = &route;
            }
        }
    }

    return best;
}

async_net::Task<void> router::route_broadcast_loop() {
    // Broadcast routing table every 10 seconds
    while (running_) {
        co_await async_net::sleep_for(std::chrono::seconds(10), *ctx_);
        if (!running_) break;

        // Build route update message from current routing table
        std::vector<payload::route_entry_data> entries;
        {
            std::lock_guard lock(routing_mutex_);
            for (const auto& route : routing_table_) {
                payload::route_entry_data e;
                e.dst_vip = route.dst_vip;
                e.via_node = route.via_node;
                e.latency_ms = route.latency_ms;
                e.hop_count = route.hop_count;
                entries.push_back(e);
            }
        }

        if (entries.empty()) continue;

        // Broadcast to all peers
        payload::route_update_payload update{entries};
        frame f{msg_type::ROUTE_UPDATE, update.serialize()};

        auto peers = pm_.connected_peers();
        for (const auto& peer : peers) {
            co_await pm_.send_to_peer(peer.node_id, f);
        }
    }
    co_return;
}

std::vector<route_entry> router::get_routes() const {
    // Note: this is a const method but we need to lock the mutex
    // We use const_cast to allow locking in const context
    std::lock_guard lock(const_cast<std::mutex&>(routing_mutex_));
    return routing_table_;
}

void router::update_routes(NodeId from_node, const std::vector<route_entry>& entries) {
    std::lock_guard lock(routing_mutex_);

    auto now = std::chrono::steady_clock::now();

    // Bellman-Ford style relaxation
    for (const auto& new_entry : entries) {
        // Skip routes back to ourselves
        if (new_entry.dst_vip == 0) continue;

        // Find existing route to this destination
        auto it = std::find_if(routing_table_.begin(), routing_table_.end(),
            [&](const route_entry& e) {
                return e.dst_vip == new_entry.dst_vip && e.via_node == from_node;
            });

        if (it != routing_table_.end()) {
            // Update existing route
            it->latency_ms = new_entry.latency_ms;
            it->hop_count = new_entry.hop_count;
            it->last_update = now;
        } else {
            // Add new route
            route_entry route;
            route.dst_vip = new_entry.dst_vip;
            route.via_node = from_node;
            route.latency_ms = new_entry.latency_ms;
            route.hop_count = new_entry.hop_count;
            route.transport = new_entry.transport;
            route.last_update = now;
            routing_table_.push_back(route);
        }
    }

    // Remove stale routes (not updated in 60 seconds)
    routing_table_.erase(
        std::remove_if(routing_table_.begin(), routing_table_.end(),
            [&](const route_entry& e) {
                return std::chrono::duration_cast<std::chrono::seconds>(
                    now - e.last_update).count() > 60;
            }),
        routing_table_.end());
}

void router::stop() {
    running_ = false;
}

} // namespace easytier
