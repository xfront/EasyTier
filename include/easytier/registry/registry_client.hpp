#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/protocol.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace easytier {

/// Registry client — connects to the registry server for node discovery.
///
/// Usage:
///   registry_client client(ctx);
///   if (co_await client.connect("127.0.0.1", 11010, node_id, udp_port, tcp_port, name)) {
///       auto nodes = co_await client.list_nodes();
///       co_await client.heartbeat();
///       // ... receive NODE_JOINED / NODE_LEFT notifications
///       co_await client.disconnect();
///   }
class registry_client {
public:
    explicit registry_client(async_net::io_context& ctx);
    ~registry_client();

    registry_client(registry_client&&) = delete;
    registry_client& operator=(registry_client&&) = delete;

    /// Connect to registry server and register this node.
    /// Returns true on success. On success, virtual_ip() returns the assigned IP.
    async_net::Task<bool> connect(const char* host, uint16_t port,
                                   NodeId node_id, uint16_t udp_port,
                                   uint16_t tcp_port, const std::string& name);

    /// Get list of online nodes (excluding self).
    async_net::Task<std::vector<node_info>> list_nodes();

    /// Send heartbeat to registry (keeps registration alive).
    async_net::Task<bool> heartbeat();

    /// Read the next server-pushed frame (NODE_JOINED, NODE_LEFT, etc.).
    /// Blocks until a frame arrives or connection is lost.
    async_net::Task<std::optional<frame>> read_notification();

    /// Disconnect from registry.
    async_net::Task<void> disconnect();

    /// Get the assigned virtual IP.
    VirtualIP virtual_ip() const { return virtual_ip_; }

    /// Get the confirmed node ID.
    NodeId node_id() const { return node_id_; }

    /// Check if connected to registry.
    bool is_connected() const { return connected_; }

private:
    /// Read a complete frame from the socket.
    async_net::Task<std::optional<frame>> read_frame();

    /// Write a complete frame to the socket.
    async_net::Task<bool> write_frame(const frame& f);

    async_net::io_context* ctx_;
    std::unique_ptr<async_net::tcp::socket> sock_;
    NodeId node_id_ = 0;
    VirtualIP virtual_ip_ = 0;
    bool connected_ = false;
};

} // namespace easytier
