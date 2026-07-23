#include <easytier/peer/peer_transport.hpp>
#include <cstdio>
#include <cstring>

namespace easytier {

peer_transport::peer_transport(async_net::io_context& ctx, uint16_t local_port)
    : ctx_(&ctx), local_port_(local_port)
{
    sock_ = std::make_unique<async_net::udp::socket>(ctx);
    if (!sock_->is_open()) {
        std::fprintf(stderr, "[p2p] failed to create UDP socket\n");
        return;
    }

    async_net::udp::endpoint ep(local_port);
    if (!sock_->bind(ep)) {
        std::fprintf(stderr, "[p2p] failed to bind UDP port %d\n", local_port);
        sock_->close();
        return;
    }

    std::fprintf(stderr, "[p2p] UDP transport bound to port %d\n", local_port);
}

peer_transport::~peer_transport() {
    close();
}

async_net::Task<bool> peer_transport::send_to(const frame& f, const std::string& ip, uint16_t port) {
    if (!is_open()) co_return false;

    auto data = f.serialize();
    async_net::udp::endpoint ep(port, ip.c_str());
    auto n = co_await sock_->async_send_to(
        async_net::const_buffer(data.data(), data.size()), ep);
    co_return n > 0;
}

async_net::Task<std::optional<peer_transport::receive_result>> peer_transport::receive() {
    if (!is_open()) co_return std::nullopt;

    // Max UDP packet size
    uint8_t buf[65536];
    async_net::udp::endpoint from;
    auto n = co_await sock_->async_receive_from(
        async_net::mutable_buffer(buf, sizeof(buf)), from);

    if (n <= 0) co_return std::nullopt;

    auto f = frame::deserialize(buf, static_cast<size_t>(n));
    if (!f) co_return std::nullopt;

    receive_result result;
    result.frm = std::move(*f);
    result.sender_ip = from.address();
    result.sender_port = from.port();
    co_return result;
}

async_net::Task<bool> peer_transport::send_ping(const std::string& ip, uint16_t port) {
    auto ping = make_ping_frame();
    co_return co_await send_to(ping, ip, port);
}

void peer_transport::close() {
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
}

} // namespace easytier
