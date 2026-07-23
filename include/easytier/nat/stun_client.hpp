#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/udp.hpp>
#include <async_net/coroutine/task.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace easytier::nat {

/// NAT type classification based on STUN tests.
enum class nat_type : uint8_t {
    unknown          = 0,
    open_internet    = 1,  ///< No NAT, public IP directly
    full_cone        = 2,  ///< Full cone NAT (UDP hole punching works easily)
    restricted_cone  = 3,  ///< Restricted cone (can send to any port on mapped IP)
    port_restricted  = 4,  ///< Port restricted (most common home router)
    symmetric        = 5,  ///< Symmetric NAT (different mapping per destination)
    blocked          = 6,  ///< UDP blocked or no response
};

/// Result of a STUN binding request.
struct stun_result {
    std::string mapped_ip;    ///< Public IP address observed by STUN server
    uint16_t    mapped_port;  ///< Public port observed by STUN server
    nat_type    nat = nat_type::unknown;
};

/// STUN client implementing RFC 5389 Binding Request/Response.
///
/// Usage:
///   stun_client client(ctx);
///   auto result = co_await client.discover("stun.l.google.com", 19302);
///   if (result) {
///       printf("Public: %s:%u\n", result->mapped_ip.c_str(), result->mapped_port);
///   }
class stun_client {
public:
    explicit stun_client(async_net::io_context& ctx);
    ~stun_client();

    /// Send a STUN Binding Request and wait for response.
    /// Returns mapped address on success, nullopt on timeout/failure.
    async_net::Task<std::optional<stun_result>> discover(
        const std::string& stun_server, uint16_t port,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

    /// Try multiple STUN servers and return the first successful result.
    async_net::Task<std::optional<stun_result>> discover_any(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

    /// Get default list of public STUN servers.
    static std::vector<std::pair<std::string, uint16_t>> default_servers();

private:
    /// Parse STUN Binding Response and extract XOR-MAPPED-ADDRESS.
    std::optional<stun_result> parse_response(const uint8_t* data, size_t len,
                                               uint32_t magic_cookie);

    async_net::io_context* ctx_;
};

/// Convert nat_type to human-readable string.
const char* nat_type_to_string(nat_type t);

} // namespace easytier::nat
