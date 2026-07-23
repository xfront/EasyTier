#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/config.hpp>
#include <easytier/common/protocol.hpp>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace easytier {

/// Registry server — central rendezvous point for node discovery.
///
/// Nodes connect via TCP and use the EasyTier protocol for:
///   - Registration (get virtual IP assignment)
///   - Node list queries
///   - Heartbeat keepalive
///   - Node join/leave notifications
///
/// The server assigns virtual IPs from the configured CIDR range.
class registry_server {
public:
    registry_server(async_net::io_context& ctx, const registry_config& config);
    ~registry_server();

    registry_server(registry_server&&) = delete;
    registry_server& operator=(registry_server&&) = delete;

    /// Run the registry server (coroutine). Accepts connections and handles nodes.
    async_net::Task<void> run();

    /// Get current online node list.
    std::vector<node_info> nodes() const;

    /// Stop the server.
    void stop();

private:
    /// Internal state for a connected node.
    struct connected_node {
        node_info info;
        VirtualIP virtual_ip = 0;
        std::chrono::steady_clock::time_point last_seen;
        int socket_fd = -1;
    };

    /// Handle a single client connection.
    async_net::Task<void> handle_client(async_net::tcp::socket sock);

    /// Read a complete frame from the socket.
    async_net::Task<std::optional<frame>> read_frame(async_net::tcp::socket& sock);

    /// Write a complete frame to the socket.
    async_net::Task<bool> write_frame(async_net::tcp::socket& sock, const frame& f);

    /// Allocate a virtual IP for a new node.
    VirtualIP allocate_virtual_ip();

    /// Remove stale nodes that haven't sent heartbeat.
    void cleanup_stale_nodes();

    /// Notify all connected clients about a node join.
    void notify_node_joined(NodeId node_id, VirtualIP vip,
                            const std::string& addr, uint16_t udp_port,
                            uint16_t tcp_port, const std::string& name);

    /// Notify all connected clients about a node leaving.
    void notify_node_left(NodeId node_id);

    /// Send a frame to a specific client fd.
    void send_to_client(int fd, const frame& f);

    async_net::io_context* ctx_;
    registry_config config_;
    std::unique_ptr<async_net::tcp::acceptor> acceptor_;
    bool running_ = false;

    // Next virtual IP to allocate (incremented for each new node)
    uint32_t next_ip_suffix_ = 1;

    // Active client tasks (kept alive until completion)
    std::set<async_net::Task<void>*> active_tasks_;
    std::mutex tasks_mutex_;

    // Connected nodes: node_id -> connected_node
    mutable std::mutex nodes_mutex_;
    std::map<NodeId, connected_node> nodes_;

    // fd -> node_id mapping (for cleanup on disconnect)
    std::map<int, NodeId> fd_to_node_;
    std::mutex fd_mutex_;

    // Client sockets for push notifications: fd -> socket pointer
    std::map<int, std::shared_ptr<async_net::tcp::socket>> client_sockets_;
};

} // namespace easytier
