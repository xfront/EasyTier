#pragma once

#include "stun_client.hpp"
#include <async_net/io/io_context.hpp>
#include <async_net/coroutine/task.hpp>
#include <string>
#include <vector>

namespace easytier::nat {

/// NAT type detector using multiple STUN requests to different servers/ports.
///
/// Detection algorithm:
/// 1. Send STUN to server1:port1 → get mapped_ip1:port1
/// 2. Send STUN to server2:port2 → get mapped_ip2:port2
/// 3. Compare mappings:
///    - Same IP and port → Cone NAT (full/restricted/port-restricted)
///    - Different port → Symmetric NAT
///    - Different IP → Symmetric NAT (rare)
///    - No response → UDP blocked
class nat_detector {
public:
    explicit nat_detector(async_net::io_context& ctx);

    /// Detect NAT type using default STUN servers.
    async_net::Task<nat_type> detect();

    /// Detect NAT type using custom STUN servers.
    async_net::Task<nat_type> detect(const std::vector<std::pair<std::string, uint16_t>>& servers);

    /// Get the last detected public address.
    const stun_result& last_result() const { return last_result_; }

    /// Get a description of the detected NAT type and recommended strategy.
    std::string describe() const;

private:
    async_net::io_context* ctx_;
    stun_result last_result_;
};

} // namespace easytier::nat
