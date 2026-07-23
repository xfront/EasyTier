#include <easytier/transport/transport_manager.hpp>
#include <cstdio>
#include <algorithm>

namespace easytier {

transport_manager::transport_manager(async_net::io_context& ctx, const node_config& config)
    : ctx_(&ctx), config_(config)
{
}

transport_manager::~transport_manager() {
    close_all();
}

void transport_manager::add_transport(std::shared_ptr<i_transport> transport) {
    std::lock_guard lock(transports_mutex_);
    transports_.push_back(transport);
    std::fprintf(stderr, "[transport-mgr] added transport type=%d\n",
                 static_cast<int>(transport->type()));
}

void transport_manager::remove_transport(transport_type type) {
    std::lock_guard lock(transports_mutex_);
    transports_.erase(
        std::remove_if(transports_.begin(), transports_.end(),
            [type](const auto& t) { return t->type() == type; }),
        transports_.end());
}

async_net::Task<bool> transport_manager::send(const uint8_t* data, size_t len,
                                               const std::string& ip, uint16_t port,
                                               transport_type preferred) {
    std::vector<std::shared_ptr<i_transport>> transports_copy;
    {
        std::lock_guard lock(transports_mutex_);
        transports_copy = transports_;
    }

    // Try preferred transport first
    for (auto& t : transports_copy) {
        if (t->type() == preferred && t->is_open()) {
            bool ok = co_await t->send(data, len, ip, port);
            if (ok) co_return true;
        }
    }

    // Fallback order: QUIC > WS > relay
    std::vector<transport_type> fallback_order = {
        transport_type::quic,
        transport_type::ws,
        transport_type::relay,
        transport_type::p2p
    };

    for (auto type : fallback_order) {
        if (type == preferred) continue;
        for (auto& t : transports_copy) {
            if (t->type() == type && t->is_open()) {
                bool ok = co_await t->send(data, len, ip, port);
                if (ok) co_return true;
            }
        }
    }

    co_return false;
}

async_net::Task<std::optional<transport_recv_result>> transport_manager::receive() {
    std::vector<std::shared_ptr<i_transport>> transports_copy;
    {
        std::lock_guard lock(transports_mutex_);
        transports_copy = transports_;
    }

    // Poll all transports for incoming data
    while (true) {
        for (auto& t : transports_copy) {
            if (!t->is_open()) continue;

            auto result = co_await t->receive();
            if (result) {
                co_return result;
            }
        }

        // No data available, yield and retry
        co_await async_net::sleep_for(std::chrono::milliseconds(10), *ctx_);
    }

    co_return std::nullopt;
}

std::vector<std::shared_ptr<i_transport>> transport_manager::get_transports() const {
    std::lock_guard lock(const_cast<std::mutex&>(transports_mutex_));
    return transports_;
}

bool transport_manager::has_transport(transport_type type) const {
    std::lock_guard lock(const_cast<std::mutex&>(transports_mutex_));
    for (const auto& t : transports_) {
        if (t->type() == type && t->is_open()) return true;
    }
    return false;
}

void transport_manager::close_all() {
    std::lock_guard lock(transports_mutex_);
    for (auto& t : transports_) {
        t->close();
    }
    transports_.clear();
}

} // namespace easytier
