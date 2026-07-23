#pragma once

#include <easytier/transport/transport.hpp>
#include <easytier/common/config.hpp>
#include <async_net/io/io_context.hpp>
#include <memory>
#include <vector>
#include <mutex>

namespace easytier {

/// Transport manager — manages multiple transport protocols and provides
/// unified send/receive interface with automatic protocol selection.
///
/// Connection priority: P2P UDP > QUIC > WSS > TCP relay
/// Automatically falls back to lower-priority transports on failure.
class transport_manager {
public:
    transport_manager(async_net::io_context& ctx, const node_config& config);
    ~transport_manager();

    /// Register a transport.
    void add_transport(std::shared_ptr<i_transport> transport);

    /// Remove a transport by type.
    void remove_transport(transport_type type);

    /// Send data using the best available transport.
    async_net::Task<bool> send(const uint8_t* data, size_t len,
                                const std::string& ip, uint16_t port,
                                transport_type preferred = transport_type::p2p);

    /// Receive data from any transport.
    async_net::Task<std::optional<transport_recv_result>> receive();

    /// Get all registered transports.
    std::vector<std::shared_ptr<i_transport>> get_transports() const;

    /// Check if a specific transport type is available.
    bool has_transport(transport_type type) const;

    /// Close all transports.
    void close_all();

private:
    async_net::io_context* ctx_;
    node_config config_;

    std::vector<std::shared_ptr<i_transport>> transports_;
    std::mutex transports_mutex_;
};

} // namespace easytier
