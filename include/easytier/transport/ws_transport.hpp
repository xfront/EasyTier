#pragma once

#include <easytier/transport/transport.hpp>
#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/http/websocket.hpp>
#include <memory>
#include <mutex>
#include <map>

namespace easytier {

/// WebSocket transport — uses WebSocket protocol over TCP for firewall-friendly communication.
///
/// Supports both WS (ws://) and WSS (wss://) modes.
/// Ideal for scenarios where UDP is blocked but HTTP/HTTPS is allowed.
/// Typically runs on port 443 or 8080.
class ws_transport : public i_transport {
public:
    ws_transport(async_net::io_context& ctx, uint16_t local_port, bool use_ssl = false);
    ~ws_transport() override;

    async_net::Task<bool> send(const uint8_t* data, size_t len,
                                const std::string& ip, uint16_t port) override;
    async_net::Task<std::optional<transport_recv_result>> receive() override;
    transport_type type() const override { return transport_type::ws; }
    bool is_open() const override { return running_; }
    void close() override;
    uint16_t local_port() const override { return local_port_; }

    /// Accept an incoming WebSocket connection.
    async_net::Task<bool> accept_connection();

private:
    async_net::io_context* ctx_;
    uint16_t local_port_;
    bool use_ssl_;
    bool running_ = false;

    std::unique_ptr<async_net::tcp::acceptor> acceptor_;

    // Connected WebSocket peers
    struct ws_peer {
        std::shared_ptr<async_net::tcp::socket> sock;
        std::unique_ptr<async_net::http::ws::connection> conn;
        std::string remote_ip;
        uint16_t remote_port;
    };
    std::map<std::string, std::shared_ptr<ws_peer>> peers_;
    std::mutex peers_mutex_;

    // Receive queue
    std::vector<transport_recv_result> recv_queue_;
    std::mutex recv_mutex_;
};

} // namespace easytier
