#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/udp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/protocol.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace easytier {

/// P2P transport layer — direct peer-to-peer communication over UDP.
///
/// Uses raw UDP sockets for communication. For the MVP, we use a simple
/// protocol over UDP without DTLS (DTLS can be added later using async_net's
/// peer_connection for production use).
///
/// Each peer_transport instance manages a single UDP socket bound to a local port.
/// It can send/receive EasyTier frames to/from remote peers identified by their
/// UDP endpoint (ip:port).
class peer_transport {
public:
    /// Create a P2P transport bound to the given local UDP port.
    peer_transport(async_net::io_context& ctx, uint16_t local_port);
    ~peer_transport();

    peer_transport(peer_transport&&) = delete;
    peer_transport& operator=(peer_transport&&) = delete;

    /// Check if the transport is open.
    bool is_open() const { return sock_ != nullptr && sock_->is_open(); }

    /// Get the local UDP port.
    uint16_t local_port() const { return local_port_; }

    /// Send a frame to a remote peer.
    async_net::Task<bool> send_to(const frame& f, const std::string& ip, uint16_t port);

    /// Receive a frame from any peer.
    /// Returns the frame and the sender's endpoint (ip, port).
    struct receive_result {
        frame frm;
        std::string sender_ip;
        uint16_t sender_port;
    };
    async_net::Task<std::optional<receive_result>> receive();

    /// Send a PING to a remote peer (for NAT traversal / keepalive).
    async_net::Task<bool> send_ping(const std::string& ip, uint16_t port);

    /// Close the transport.
    void close();

private:
    async_net::io_context* ctx_;
    std::unique_ptr<async_net::udp::socket> sock_;
    uint16_t local_port_;
};

} // namespace easytier
