#include "easytier/web/web_api.hpp"
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/spawn.hpp>
#include <sstream>
#include <cstring>

namespace easytier::web {

web_api::web_api(async_net::io_context& ctx, uint16_t port)
    : ctx_(&ctx), port_(port) {}

web_api::~web_api() {
    stop();
}

async_net::Task<void> web_api::start() {
    running_ = true;
    start_time_ = std::chrono::steady_clock::now();

    acceptor_ = std::make_unique<async_net::tcp::acceptor>(*ctx_, port_, "127.0.0.1");
    while (running_) {
        auto sock = co_await acceptor_->async_accept();

        if (!sock.is_open() || !running_) break;

        // Handle connection in a new coroutine
        async_net::spawn(handle_connection(std::move(sock)));
    }
}

void web_api::stop() {
    running_ = false;
    if (acceptor_ && acceptor_->is_open()) {
        acceptor_->close();
    }
}

async_net::Task<void> web_api::handle_connection(async_net::tcp::socket sock) {
    // Read HTTP request
    uint8_t buffer[4096];
    auto nread = co_await sock.async_read_some(async_net::mutable_buffer(buffer, sizeof(buffer)));

    if (nread <= 0) co_return;

    std::string request(reinterpret_cast<char*>(buffer), nread);

    // Parse request line
    std::istringstream iss(request);
    std::string method, path, version;
    iss >> method >> path >> version;

    // Route requests
    if (path == "/api/status" && method == "GET") {
        co_await send_response(sock, 200, "application/json", status_json());
    } else if (path == "/api/peers" && method == "GET") {
        co_await send_response(sock, 200, "application/json", peers_json());
    } else if (path == "/" || path == "/index.html") {
        co_await send_response(sock, 200, "text/html", web_ui_html());
    } else {
        co_await send_response(sock, 404, "text/plain", "Not Found");
    }
}

async_net::Task<void> web_api::send_response(
    async_net::tcp::socket& sock,
    int status_code,
    const std::string& content_type,
    const std::string& body) {

    std::string status_text = (status_code == 200) ? "OK" : "Not Found";
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "\r\n"
        << body;

    std::string response = oss.str();
    co_await sock.async_write(async_net::const_buffer(response.data(), response.size()));
}

std::string web_api::status_json() const {
    if (!callbacks_.get_status) return "{}";

    auto status = callbacks_.get_status();
    std::ostringstream oss;
    oss << "{"
        << "\"node_id\":" << status.node_id << ","
        << "\"virtual_ip\":\"" << virtual_ip_to_string(status.virtual_ip) << "\","
        << "\"name\":\"" << status.name << "\","
        << "\"version\":\"" << status.version << "\","
        << "\"uptime\":" << status.uptime_seconds << ","
        << "\"peer_count\":" << status.peer_count << ","
        << "\"route_count\":" << status.route_count
        << "}";
    return oss.str();
}

std::string web_api::peers_json() const {
    if (!callbacks_.get_peers) return "[]";

    auto peers = callbacks_.get_peers();
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < peers.size(); ++i) {
        if (i > 0) oss << ",";
        const auto& p = peers[i];
        oss << "{"
            << "\"node_id\":" << p.node_id << ","
            << "\"virtual_ip\":\"" << virtual_ip_to_string(p.virtual_ip) << "\","
            << "\"name\":\"" << p.name << "\","
            << "\"type\":\"" << (p.type == transport_type::p2p ? "p2p" : "relay") << "\","
            << "\"state\":\"" << (p.state == connection_state::connected ? "connected" : "disconnected") << "\","
            << "\"latency_ms\":" << p.latency_ms << ","
            << "\"bytes_sent\":" << p.bytes_sent << ","
            << "\"bytes_recv\":" << p.bytes_recv
            << "}";
    }
    oss << "]";
    return oss.str();
}

std::string web_api::web_ui_html() const {
    return R"HTML(<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EasyTier Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; margin-bottom: 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { color: #555; margin-bottom: 15px; font-size: 18px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .status-item { padding: 15px; background: #f9f9f9; border-radius: 6px; }
        .status-item label { display: block; color: #888; font-size: 12px; margin-bottom: 5px; }
        .status-item value { display: block; color: #333; font-size: 16px; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f9f9f9; font-weight: 600; color: #555; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge.connected { background: #d4edda; color: #155724; }
        .badge.disconnected { background: #f8d7da; color: #721c24; }
        .badge.p2p { background: #d1ecf1; color: #0c5460; }
        .badge.relay { background: #fff3cd; color: #856404; }
        #refresh-btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; }
        #refresh-btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 EasyTier Dashboard</h1>

        <div class="card">
            <h2>Node Status</h2>
            <div class="status-grid" id="status-grid">
                <div class="status-item"><label>Node ID</label><value id="node-id">-</value></div>
                <div class="status-item"><label>Virtual IP</label><value id="virtual-ip">-</value></div>
                <div class="status-item"><label>Name</label><value id="node-name">-</value></div>
                <div class="status-item"><label>Uptime</label><value id="uptime">-</value></div>
                <div class="status-item"><label>Peers</label><value id="peer-count">-</value></div>
            </div>
        </div>

        <div class="card">
            <h2>Connected Peers <button id="refresh-btn" onclick="loadData()">Refresh</button></h2>
            <table>
                <thead>
                    <tr><th>Node ID</th><th>Virtual IP</th><th>Name</th><th>Type</th><th>State</th><th>Latency</th></tr>
                </thead>
                <tbody id="peers-table"></tbody>
            </table>
        </div>
    </div>

    <script>
        async function loadData() {
            try {
                const [statusResp, peersResp] = await Promise.all([
                    fetch('/api/status'),
                    fetch('/api/peers')
                ]);
                const status = await statusResp.json();
                const peers = await peersResp.json();

                document.getElementById('node-id').textContent = status.node_id;
                document.getElementById('virtual-ip').textContent = status.virtual_ip;
                document.getElementById('node-name').textContent = status.name;
                document.getElementById('uptime').textContent = status.uptime + 's';
                document.getElementById('peer-count').textContent = status.peer_count;

                const tbody = document.getElementById('peers-table');
                tbody.innerHTML = peers.map(p => `
                    <tr>
                        <td>${p.node_id}</td>
                        <td>${p.virtual_ip}</td>
                        <td>${p.name}</td>
                        <td><span class="badge ${p.type}">${p.type}</span></td>
                        <td><span class="badge ${p.state}">${p.state}</span></td>
                        <td>${p.latency_ms}ms</td>
                    </tr>
                `).join('');
            } catch (e) {
                console.error('Failed to load data:', e);
            }
        }

        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>)HTML";
}

} // namespace easytier::web
