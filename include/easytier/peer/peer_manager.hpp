#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/config.hpp>
#include <easytier/common/protocol.hpp>
#include <easytier/peer/peer_transport.hpp>
#include <easytier/peer/relay_transport.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace easytier {

/// Information about a connected peer.
struct peer_state {
    NodeId          node_id = 0;
    VirtualIP       virtual_ip = 0;
    node_info       info;
    transport_type  transport = transport_type::p2p;
    connection_state state = connection_state::disconnected;

    // P2P transport (UDP)
    // Shared because peer_transport is shared across operations
    std::shared_ptr<peer_transport> p2p;

    // Relay transport (TCP) - one per peer
    std::unique_ptr<relay_transport> relay;

    std::chrono::steady_clock::time_point last_seen;

    // Latency measurement (milliseconds)
    uint32_t latency_ms = 0;
    std::chrono::steady_clock::time_point last_ping_sent;
    uint32_t ping_seq = 0;
};

/// Peer manager — manages connections to all remote peers.
///
/// Responsibilities:
///   - Maintain connections to all known peers (P2P or relay)
///   - Try P2P first, fall back to relay
///   - Provide unified send/receive interface
///   - Health check and reconnection
class peer_manager {
public:
    /// Callback type for received data packets.
    using data_callback = std::function<void(NodeId src_node, VirtualIP dst_vip,
                                              const uint8_t* data, size_t len)>;

    peer_manager(async_net::io_context& ctx, const node_config& config,
                 NodeId my_node_id, VirtualIP my_vip);
    ~peer_manager();

    peer_manager(peer_manager&&) = delete;
    peer_manager& operator=(peer_manager&&) = delete;

    /// Start the peer manager (coroutine).
    async_net::Task<void> start();

    /// Stop the peer manager.
    void stop();

    /// Add a new peer to connect to (called when registry notifies about new nodes).
    void add_peer(const node_info& info);

    /// Remove a peer (called when registry notifies about node leaving).
    void remove_peer(NodeId node_id);

    /// Send an IP packet to a specific virtual IP.
    /// The peer_manager determines the transport path (P2P or relay).
    async_net::Task<bool> send_to_virtual_ip(VirtualIP dst_vip,
                                              const uint8_t* data, size_t len);

    /// Send a frame to a specific peer by node ID.
    async_net::Task<bool> send_to_peer(NodeId node_id, const frame& f);

    /// Set the callback for received data packets (from peers to TUN).
    void set_data_callback(data_callback cb);

    /// Get the list of connected peers.
    std::vector<node_info> connected_peers() const;

    /// Get the latency to a specific peer (in milliseconds).
    uint32_t get_peer_latency(NodeId node_id) const;

    /// Get all peer latencies.
    std::map<NodeId, uint32_t> all_peer_latencies() const;

    /// Get the P2P transport (for external use).
    std::shared_ptr<peer_transport> p2p_transport() const { return p2p_transport_; }

private:
    /// Try to establish a P2P connection to a peer.
    async_net::Task<bool> try_p2p_connect(peer_state& ps);

    /// Try to establish a relay connection to a peer.
    async_net::Task<bool> try_relay_connect(peer_state& ps);

    /// Background task: receive from P2P transport and dispatch.
    async_net::Task<void> p2p_receive_loop();

    /// Background task: periodic keepalive and health check.
    async_net::Task<void> keepalive_loop();

    /// Find peer by virtual IP.
    peer_state* find_peer_by_vip(VirtualIP vip);

    async_net::io_context* ctx_;
    node_config config_;
    NodeId my_node_id_;
    VirtualIP my_vip_;
    bool running_ = false;

    // P2P transport (shared UDP socket)
    std::shared_ptr<peer_transport> p2p_transport_;

    // Relay acceptor (TCP, for incoming relay connections)
    std::unique_ptr<async_net::tcp::acceptor> relay_acceptor_;

    // Connected peers: node_id -> peer_state
    std::map<NodeId, peer_state> peers_;
    mutable std::mutex peers_mutex_;

    // Active tasks
    std::set<async_net::Task<void>*> active_tasks_;
    std::mutex tasks_mutex_;

    // Data received callback
    data_callback data_cb_;
};

} // namespace easytier
