#include <easytier/transport/quic_transport.hpp>
#include <cstdio>

namespace easytier {

quic_transport::quic_transport(async_net::io_context& ctx, uint16_t local_port)
    : ctx_(&ctx), local_port_(local_port)
{
    // QUIC transport requires HTTP/3 support in async_net
#ifdef ASYNC_NET_HAS_HTTP3
    udp_sock_ = std::make_unique<async_net::udp::socket>(*ctx_);
    if (udp_sock_->bind(local_port_)) {
        running_ = true;
        std::fprintf(stderr, "[quic-transport] listening on UDP port %d\n", local_port_);
    } else {
        std::fprintf(stderr, "[quic-transport] failed to bind port %d\n", local_port_);
    }
#else
    std::fprintf(stderr, "[quic-transport] QUIC not available (ASYNC_NET_HAS_HTTP3 not defined)\n");
#endif
}

quic_transport::~quic_transport() {
    close();
}

async_net::Task<bool> quic_transport::send(const uint8_t* data, size_t len,
                                            const std::string& ip, uint16_t port) {
#ifndef ASYNC_NET_HAS_HTTP3
    co_return false;
#else
    if (!running_ || !udp_sock_) co_return false;

    // For now, use raw UDP with QUIC framing
    // Full QUIC session management would use http3_session
    async_net::udp::endpoint ep(port, ip.c_str());
    auto sent = co_await udp_sock_->async_send_to(
        async_net::const_buffer(data, len), ep);
    co_return sent > 0;
#endif
}

async_net::Task<std::optional<transport_recv_result>> quic_transport::receive() {
#ifndef ASYNC_NET_HAS_HTTP3
    co_return std::nullopt;
#else
    if (!running_ || !udp_sock_) co_return std::nullopt;

    uint8_t buf[65536];
    async_net::udp::endpoint ep;

    auto n = co_await udp_sock_->async_receive_from(
        async_net::mutable_buffer(buf, sizeof(buf)), ep);

    if (n <= 0) co_return std::nullopt;

    transport_recv_result result;
    result.data.assign(buf, buf + n);
    result.sender_ip = ep.address();
    result.sender_port = ep.port();
    result.transport = transport_type::quic;

    co_return result;
#endif
}

void quic_transport::close() {
    running_ = false;
    if (udp_sock_) {
        udp_sock_->close();
    }
}

} // namespace easytier
