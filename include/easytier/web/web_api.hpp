#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/config.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace easytier::web {

/// Peer status for web API.
struct peer_status {
    NodeId          node_id = 0;
    VirtualIP       virtual_ip = 0;
    std::string     name;
    transport_type  type = transport_type::p2p;
    connection_state state = connection_state::disconnected;
    uint32_t        latency_ms = 0;
    uint64_t        bytes_sent = 0;
    uint64_t        bytes_recv = 0;
};

/// Node status for web API.
struct node_status {
    NodeId      node_id = 0;
    VirtualIP   virtual_ip = 0;
    std::string name;
    std::string version = "1.0.0";
    uint64_t    uptime_seconds = 0;
    size_t      peer_count = 0;
    size_t      route_count = 0;
};

/// Callbacks for retrieving data from the node.
struct web_callbacks {
    std::function<node_status()> get_status;
    std::function<std::vector<peer_status>()> get_peers;
    std::function<bool(const std::string& ip, uint16_t port)> connect_peer;
    std::function<bool(NodeId node_id)> disconnect_peer;
};

/// HTTP REST API server for EasyTier node management.
///
/// Endpoints:
///   GET  /api/status  — Node status (ID, VIP, uptime, version)
///   GET  /api/peers   — Online peer list
///   GET  /api/routes  — Routing table
///   GET  /api/config  — Current configuration
///   PUT  /api/config  — Update configuration
///   POST /api/peers/connect    — Manually add peer
///   DELETE /api/peers/:id      — Disconnect peer
///   GET  /          — Web UI (single-page HTML)
///
/// Default: listens on 127.0.0.1:11080 (local access only).
class web_api {
public:
    web_api(async_net::io_context& ctx, uint16_t port = 11080);
    ~web_api();

    /// Set callbacks for retrieving node data.
    void set_callbacks(web_callbacks cbs) { callbacks_ = std::move(cbs); }

    /// Start the HTTP server.
    async_net::Task<void> start();

    /// Stop the HTTP server.
    void stop();

    /// Get the listening port.
    uint16_t port() const { return port_; }

private:
    /// Handle an HTTP request.
    async_net::Task<void> handle_connection(async_net::tcp::socket sock);

    /// Generate JSON response for /api/status.
    std::string status_json() const;

    /// Generate JSON response for /api/peers.
    std::string peers_json() const;

    /// Generate the web UI HTML.
    std::string web_ui_html() const;

    /// Send HTTP response.
    async_net::Task<void> send_response(async_net::tcp::socket& sock,
                                         int status_code,
                                         const std::string& content_type,
                                         const std::string& body);

    async_net::io_context* ctx_;
    uint16_t port_;
    std::unique_ptr<async_net::tcp::acceptor> acceptor_;
    web_callbacks callbacks_;
    bool running_ = false;
    std::chrono::steady_clock::time_point start_time_;
};

} // namespace easytier::web
