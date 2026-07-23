#include <easytier/transport/ws_transport.hpp>
#include <cstdio>
#include <cstring>

namespace easytier {

ws_transport::ws_transport(async_net::io_context& ctx, uint16_t local_port, bool use_ssl)
    : ctx_(&ctx), local_port_(local_port), use_ssl_(use_ssl)
{
    acceptor_ = std::make_unique<async_net::tcp::acceptor>(*ctx_, local_port_);
    if (acceptor_->is_open()) {
        running_ = true;
        std::fprintf(stderr, "[ws-transport] listening on port %d (%s)\n",
                     local_port_, use_ssl ? "WSS" : "WS");
    } else {
        std::fprintf(stderr, "[ws-transport] failed to bind port %d\n", local_port_);
    }
}

ws_transport::~ws_transport() {
    close();
}

async_net::Task<bool> ws_transport::accept_connection() {
    if (!acceptor_ || !acceptor_->is_open()) co_return false;

    auto sock = co_await acceptor_->async_accept();
    if (!sock.is_open()) co_return false;

    // Perform WebSocket handshake
    auto ws_conn = async_net::http::ws::connection::accept(std::move(sock));
    if (!ws_conn) co_return false;

    auto peer = std::make_shared<ws_peer>();
    peer->conn = std::make_unique<async_net::http::ws::connection>(std::move(*ws_conn));
    peer->remote_ip = "unknown";
    peer->remote_port = 0;

    std::lock_guard lock(peers_mutex_);
    peers_["accepted"] = peer;

    co_return true;
}

async_net::Task<bool> ws_transport::send(const uint8_t* data, size_t len,
                                          const std::string& ip, uint16_t port) {
    std::string key = ip + ":" + std::to_string(port);

    std::shared_ptr<ws_peer> peer;
    {
        std::lock_guard lock(peers_mutex_);
        auto it = peers_.find(key);
        if (it == peers_.end()) {
            // Need to establish WebSocket connection first
            auto sock = std::make_shared<async_net::tcp::socket>(*ctx_);
            bool connected = co_await sock->async_connect(ip.c_str(), port);
            if (!connected) co_return false;

            // WebSocket handshake as client
            std::string host = ip + ":" + std::to_string(port);
            auto ws_conn = async_net::http::ws::connection::connect(std::move(*sock), host, "/easytier");
            if (!ws_conn) co_return false;

            peer = std::make_shared<ws_peer>();
            peer->sock = std::make_shared<async_net::tcp::socket>(*ctx_);
            peer->conn = std::make_unique<async_net::http::ws::connection>(std::move(*ws_conn));
            peer->remote_ip = ip;
            peer->remote_port = port;
            peers_[key] = peer;
        } else {
            peer = it->second;
        }
    }

    if (!peer || !peer->conn) co_return false;

    // Send as binary WebSocket frame
    async_net::http::ws::frame ws_frame;
    ws_frame.fin = true;
    ws_frame.op = async_net::http::ws::opcode::binary;
    ws_frame.payload.assign(reinterpret_cast<const char*>(data), len);

    co_return co_await peer->conn->send(ws_frame);
}

async_net::Task<std::optional<transport_recv_result>> ws_transport::receive() {
    // Check queue first
    {
        std::lock_guard lock(recv_mutex_);
        if (!recv_queue_.empty()) {
            auto result = std::move(recv_queue_.front());
            recv_queue_.erase(recv_queue_.begin());
            co_return result;
        }
    }

    // Wait for data from any peer
    while (running_) {
        std::vector<std::shared_ptr<ws_peer>> peers_copy;
        {
            std::lock_guard lock(peers_mutex_);
            for (auto& [key, peer] : peers_) {
                peers_copy.push_back(peer);
            }
        }

        for (auto& peer : peers_copy) {
            if (!peer || !peer->conn) continue;

            auto frame = co_await peer->conn->receive();
            if (frame && frame->op == async_net::http::ws::opcode::binary) {
                transport_recv_result result;
                result.data.assign(frame->payload.begin(), frame->payload.end());
                result.sender_ip = peer->remote_ip;
                result.sender_port = peer->remote_port;
                result.transport = transport_type::ws;
                co_return result;
            }
        }

        // No data available, yield and retry
        co_await async_net::sleep_for(std::chrono::milliseconds(10), *ctx_);
    }

    co_return std::nullopt;
}

void ws_transport::close() {
    running_ = false;
    if (acceptor_) {
        acceptor_->close();
    }
    std::lock_guard lock(peers_mutex_);
    peers_.clear();
}

} // namespace easytier
