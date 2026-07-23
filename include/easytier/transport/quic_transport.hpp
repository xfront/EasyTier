#pragma once

#include <easytier/transport/transport.hpp>
#include <async_net/io/io_context.hpp>
#include <async_net/io/udp.hpp>
#include <memory>
#include <mutex>
#include <vector>

namespace easytier {

/// QUIC transport — uses QUIC protocol (via ngtcp2) for reliable, multiplexed streams.
///
/// Benefits:
///   - 0-RTT connection establishment
///   - Built-in congestion control
///   - Stream multiplexing without head-of-line blocking
///   - Works well in high-loss environments
///
/// Requires async_net HTTP/3 support (ASYNC_NET_HAS_HTTP3).
class quic_transport : public i_transport {
public:
    quic_transport(async_net::io_context& ctx, uint16_t local_port);
    ~quic_transport() override;

    async_net::Task<bool> send(const uint8_t* data, size_t len,
                                const std::string& ip, uint16_t port) override;
    async_net::Task<std::optional<transport_recv_result>> receive() override;
    transport_type type() const override { return transport_type::quic; }
    bool is_open() const override { return running_; }
    void close() override;
    uint16_t local_port() const override { return local_port_; }

private:
    async_net::io_context* ctx_;
    uint16_t local_port_;
    bool running_ = false;

    // QUIC session management
    std::unique_ptr<async_net::udp::socket> udp_sock_;

    // Receive queue
    std::vector<transport_recv_result> recv_queue_;
    std::mutex recv_mutex_;
};

} // namespace easytier
