#pragma once

#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace easytier {

/// Result of a receive operation.
struct transport_recv_result {
    std::vector<uint8_t> data;
    std::string sender_ip;
    uint16_t sender_port;
    transport_type transport;
};

/// Abstract transport interface for multi-protocol support.
///
/// All transport implementations (UDP, TCP, WebSocket, QUIC, KCP) must
/// implement this interface to be managed by the transport_manager.
class i_transport {
public:
    virtual ~i_transport() = default;

    /// Send data to a remote endpoint.
    virtual async_net::Task<bool> send(const uint8_t* data, size_t len,
                                        const std::string& ip, uint16_t port) = 0;

    /// Receive data from any remote endpoint.
    virtual async_net::Task<std::optional<transport_recv_result>> receive() = 0;

    /// Get the transport type.
    virtual transport_type type() const = 0;

    /// Check if the transport is open and ready.
    virtual bool is_open() const = 0;

    /// Close the transport.
    virtual void close() = 0;

    /// Get the local port this transport is bound to.
    virtual uint16_t local_port() const = 0;
};

} // namespace easytier
