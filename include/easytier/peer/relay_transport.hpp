#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/protocol.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace easytier {

/// Relay transport — TCP-based relay connection to a peer through an intermediate node.
///
/// When P2P direct connection fails, nodes can communicate through a relay node.
/// The relay transport establishes a TCP connection to the relay server running
/// on the remote peer (or intermediate node) and forwards EasyTier frames.
///
/// For the MVP, this is a simple TCP connection that sends/receives frames.
class relay_transport {
public:
    /// Create a relay transport.
    explicit relay_transport(async_net::io_context& ctx);
    ~relay_transport();

    relay_transport(relay_transport&&) = delete;
    relay_transport& operator=(relay_transport&&) = delete;

    /// Connect to a remote peer's relay TCP port.
    async_net::Task<bool> connect(const std::string& ip, uint16_t port);

    /// Perform handshake after connecting.
    async_net::Task<bool> handshake(NodeId my_node_id, VirtualIP my_vip);

    /// Check if connected.
    bool is_connected() const { return connected_; }

    /// Send a frame through the relay.
    async_net::Task<bool> send(const frame& f);

    /// Receive a frame from the relay.
    async_net::Task<std::optional<frame>> receive();

    /// Get the remote peer's node ID (after handshake).
    NodeId remote_node_id() const { return remote_node_id_; }

    /// Get the remote peer's virtual IP (after handshake).
    VirtualIP remote_virtual_ip() const { return remote_vip_; }

    /// Close the connection.
    void close();

private:
    /// Read a complete frame from the socket.
    async_net::Task<std::optional<frame>> read_frame();

    async_net::io_context* ctx_;
    std::unique_ptr<async_net::tcp::socket> sock_;
    bool connected_ = false;
    NodeId remote_node_id_ = 0;
    VirtualIP remote_vip_ = 0;
};

} // namespace easytier
