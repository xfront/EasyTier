#pragma once

#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/tun/tun_device.hpp>
#include <easytier/peer/peer_manager.hpp>
#include <cstdint>
#include <atomic>
#include <vector>
#include <chrono>
#include <mutex>

namespace easytier {

/// Route entry with metrics for smart routing.
struct route_entry {
    VirtualIP dst_vip = 0;           // Destination virtual IP
    NodeId    via_node = 0;          // Next hop node ID
    uint32_t  latency_ms = 0;        // Total latency (milliseconds)
    uint8_t   hop_count = 1;         // Number of hops
    transport_type transport = transport_type::p2p;
    std::chrono::steady_clock::time_point last_update;

    /// Calculate route cost (lower is better).
    /// Formula: latency * 0.7 + hop_count * 10
    double cost() const {
        return latency_ms * 0.7 + hop_count * 10.0;
    }
};

/// Virtual network router with smart routing.
///
/// Bridges the TUN device and the peer_manager:
///   - TUN -> Network: reads IP packets from TUN, extracts destination IP,
///     looks up the best route, and forwards via peer_manager.
///   - Network -> TUN: receives IP packets from peer_manager, writes to TUN.
///
/// Smart routing features:
///   - Latency-based path selection
///   - Multi-path support with automatic failover
///   - Distance-vector routing protocol for route discovery
class router {
public:
    router(async_net::io_context& ctx, tun_device& tun, peer_manager& pm);
    ~router();

    router(router&&) = delete;
    router& operator=(router&&) = delete;

    /// Start the router (coroutine). Runs both directions.
    async_net::Task<void> start();

    /// Stop the router.
    void stop();

    /// Get packet counters.
    uint64_t tun_to_net_packets() const { return tun_to_net_.load(); }
    uint64_t net_to_tun_packets() const { return net_to_tun_.load(); }

    /// Get the routing table.
    std::vector<route_entry> get_routes() const;

    /// Update route table from neighbor (distance-vector protocol).
    void update_routes(NodeId from_node, const std::vector<route_entry>& entries);

private:
    /// TUN -> Network: read from TUN, extract dst IP, forward to peer.
    async_net::Task<void> tun_to_net_loop();

    /// Network -> TUN: callback from peer_manager, write to TUN.
    void net_to_tun_handler(NodeId src_node, VirtualIP dst_vip,
                            const uint8_t* data, size_t len);

    /// Extract destination IP from an IPv4 packet.
    /// The IP header starts with the version/IHL byte.
    /// Returns the destination IP as VirtualIP (network byte order).
    static VirtualIP extract_dst_ip(const uint8_t* ip_packet, size_t len);

    /// Check if a VirtualIP belongs to our virtual network.
    bool is_local_network(VirtualIP vip) const;

    /// Select the best route to a destination.
    route_entry* select_route(VirtualIP dst_vip);

    /// Periodic route table broadcast (distance-vector protocol).
    async_net::Task<void> route_broadcast_loop();

    async_net::io_context* ctx_;
    tun_device& tun_;
    peer_manager& pm_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> tun_to_net_{0};
    std::atomic<uint64_t> net_to_tun_{0};

    // Buffer for TUN reads
    static constexpr size_t TUN_BUF_SIZE = 2048;
    uint8_t tun_buf_[TUN_BUF_SIZE];

    // Smart routing table
    std::vector<route_entry> routing_table_;
    std::mutex routing_mutex_;
};

} // namespace easytier
