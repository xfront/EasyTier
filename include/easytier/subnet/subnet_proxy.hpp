#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/protocol.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <optional>
#include <functional>

namespace easytier {

/// Subnet route entry: maps a CIDR subnet to the node that owns it.
struct subnet_route {
    uint32_t    network;        // Network address (network byte order)
    uint8_t     prefix_len;     // CIDR prefix length (0-32)
    NodeId      owner_node;     // Node that announced this subnet
    VirtualIP   owner_vip;      // Virtual IP of the owner node
    std::chrono::steady_clock::time_point last_announce;

    /// Check if an IP address belongs to this subnet.
    bool contains(uint32_t ip) const {
        if (prefix_len == 0) return true;
        uint32_t mask = htonl(~((1U << (32 - prefix_len)) - 1));
        return (ip & mask) == (network & mask);
    }
};

/// Callback for forwarding packets to subnet owner's TUN device.
using subnet_forward_cb = std::function<bool(NodeId owner, const uint8_t* data, size_t len)>;

/// Subnet proxy — allows nodes to share their local subnets with the virtual network.
///
/// When a node announces a subnet (e.g. 192.168.1.0/24), other nodes can route
/// packets destined for that subnet through the announcing node.
///
/// The announcing node receives these packets and writes them to its local TUN device,
/// effectively bridging the virtual network with the physical subnet.
class subnet_proxy {
public:
    subnet_proxy();
    ~subnet_proxy();

    /// Announce a local subnet (e.g. "192.168.1.0/24").
    /// This subnet will be broadcast to all peers.
    void announce_subnet(const std::string& cidr, NodeId my_node_id, VirtualIP my_vip);

    /// Remove a previously announced subnet.
    void withdraw_subnet(const std::string& cidr);

    /// Process a subnet announcement from a remote peer.
    void handle_announcement(NodeId from_node, VirtualIP from_vip,
                             const std::vector<subnet_route>& routes);

    /// Look up which node owns a given IP address.
    /// Returns the node ID if the IP belongs to an announced subnet.
    std::optional<NodeId> lookup_subnet(uint32_t ip) const;

    /// Get all known subnet routes.
    std::vector<subnet_route> get_routes() const;

    /// Get the subnets this node has announced.
    std::vector<subnet_route> get_announced() const;

    /// Build subnet announcement payload for broadcasting.
    std::vector<payload::route_entry_data> build_announcements() const;

    /// Set the forward callback for packets destined to local subnets.
    void set_forward_callback(subnet_forward_cb cb);

    /// Check if an IP belongs to any announced subnet.
    bool is_subnet_traffic(uint32_t ip) const;

private:
    /// Parse "a.b.c.d/n" into network address and prefix length.
    static bool parse_cidr(const std::string& cidr, uint32_t& network, uint8_t& prefix_len);

    // Known subnet routes (from remote peers)
    std::vector<subnet_route> routes_;
    mutable std::mutex routes_mutex_;

    // Subnets this node has announced
    std::vector<subnet_route> announced_;
    mutable std::mutex announced_mutex_;

    // Forward callback
    subnet_forward_cb forward_cb_;
};

} // namespace easytier
