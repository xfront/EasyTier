#pragma once

#include "routing_table.hpp"
#include "dht_message.hpp"
#include <async_net/io/io_context.hpp>
#include <async_net/io/udp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace easytier::dht {

/// Bootstrap node configuration.
struct bootstrap_node {
    std::string ip;
    uint16_t    udp_port = 0;
    uint16_t    tcp_port = 0;
    node_id     id;  ///< Optional: known node ID
};

/// Value stored in the DHT (virtual IP → node mapping).
struct dht_value {
    node_id    key;
    node_id    owner_node_id;
    std::string owner_ip;
    std::chrono::steady_clock::time_point expires_at;
};

/// Kademlia DHT node for decentralized peer discovery.
///
/// Responsibilities:
/// - Maintain routing table of known nodes
/// - Handle PING/PONG for liveness
/// - Handle FIND_NODE/FIND_NODE_RESPONSE for node lookup
/// - Handle REGISTER_VALUE/FIND_VALUE for VIP→NodeID mapping
/// - Periodic refresh of routing table
///
/// Usage:
///   dht_node node(ctx, my_id, udp_port);
///   co_await node.start(bootstrap_nodes);
///   auto vip_node = co_await node.find_node_by_vip(vip);
class dht_node {
public:
    dht_node(async_net::io_context& ctx, const node_id& my_id, uint16_t udp_port);
    ~dht_node();

    /// Start the DHT node: connect to bootstrap nodes and begin listening.
    async_net::Task<void> start(const std::vector<bootstrap_node>& boots);

    /// Stop the DHT node.
    void stop();

    /// Find the node responsible for a virtual IP.
    async_net::Task<std::optional<node_id>> find_node_by_vip(VirtualIP vip);

    /// Find K nearest nodes to a target ID.
    async_net::Task<std::vector<node_info>> find_nearest(const node_id& target, int k = 20);

    /// Announce that this node owns a virtual IP.
    void announce_vip(VirtualIP vip, const node_id& node_id);

    /// Get the routing table.
    const routing_table& table() const { return table_; }

    /// Get the node ID.
    const node_id& id() const { return my_id_; }

    /// Get the UDP port.
    uint16_t udp_port() const { return udp_port_; }

    /// Set callback for when a new node is discovered.
    using node_discovered_cb = std::function<void(const node_info&)>;
    void on_node_discovered(node_discovered_cb cb) { on_discovered_ = std::move(cb); }

private:
    /// Main receive loop.
    async_net::Task<void> receive_loop();

    /// Handle incoming DHT messages.
    async_net::Task<void> handle_message(const uint8_t* data, size_t len,
                                          const std::string& sender_ip, uint16_t sender_port);

    /// Send a DHT message to a node.
    async_net::Task<bool> send_message(const std::vector<uint8_t>& data,
                                        const std::string& ip, uint16_t port);

    /// Bootstrap: connect to initial nodes.
    async_net::Task<void> bootstrap(const std::vector<bootstrap_node>& boots);

    /// Periodic refresh of routing table.
    async_net::Task<void> refresh_loop();

    /// Periodic cleanup of expired values.
    async_net::Task<void> cleanup_loop();

    /// Iterative lookup: find K nearest nodes by querying neighbors.
    async_net::Task<std::vector<node_info>> iterative_lookup(const node_id& target, int k);

    async_net::io_context* ctx_;
    node_id my_id_;
    uint16_t udp_port_;
    routing_table table_;
    std::unique_ptr<async_net::udp::socket> sock_;
    bool running_ = false;
    uint16_t next_transaction_id_ = 0;

    /// VIP → NodeID mapping (local cache).
    std::unordered_map<uint32_t, dht_value> values_;

    /// Callback for discovered nodes.
    node_discovered_cb on_discovered_;
};

} // namespace easytier::dht
