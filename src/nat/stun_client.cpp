#include "easytier/nat/stun_client.hpp"
#include <async_net/coroutine/spawn.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstring>
#include <random>
#include <arpa/inet.h>
#include <netdb.h>

namespace easytier::nat {

// STUN protocol constants (RFC 5389)
namespace stun {
    constexpr uint16_t BINDING_REQUEST  = 0x0001;
    constexpr uint16_t BINDING_RESPONSE = 0x0101;
    constexpr uint16_t BINDING_ERROR    = 0x0111;
    constexpr uint32_t MAGIC_COOKIE     = 0x2112A442;

    // Attribute types
    constexpr uint16_t MAPPED_ADDRESS     = 0x0001;
    constexpr uint16_t XOR_MAPPED_ADDRESS = 0x0020;

    // Address families
    constexpr uint8_t AF_IPV4 = 0x01;
    constexpr uint8_t AF_IPV6 = 0x02;

    // Header: [type:2][length:2][magic_cookie:4][transaction_id:12]
    constexpr size_t HEADER_LEN = 20;
}

namespace {

// Resolve hostname to IP address
std::string resolve_host(const std::string& hostname) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        return "";
    }

    char ip[INET_ADDRSTRLEN];
    auto* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);
    return std::string(ip);
}

// Generate random transaction ID
std::array<uint8_t, 12> generate_transaction_id() {
    std::array<uint8_t, 12> id;
    std::random_device rd;
    std::mt19937 gen(rd());
    for (auto& b : id) b = gen() & 0xff;
    return id;
}

} // anonymous namespace

stun_client::stun_client(async_net::io_context& ctx) : ctx_(&ctx) {}

stun_client::~stun_client() = default;

async_net::Task<std::optional<stun_result>> stun_client::discover(
    const std::string& stun_server, uint16_t port,
    std::chrono::milliseconds timeout) {

    // Resolve hostname
    std::string server_ip = resolve_host(stun_server);
    if (server_ip.empty()) {
        co_return std::nullopt;
    }

    // Create UDP socket
    async_net::udp::socket sock(*ctx_);

    // Build STUN Binding Request
    auto txn_id = generate_transaction_id();
    uint8_t request[stun::HEADER_LEN];
    request[0] = (stun::BINDING_REQUEST >> 8) & 0xff;
    request[1] = stun::BINDING_REQUEST & 0xff;
    request[2] = 0; request[3] = 0;  // Message length = 0 (no attributes)
    request[4] = (stun::MAGIC_COOKIE >> 24) & 0xff;
    request[5] = (stun::MAGIC_COOKIE >> 16) & 0xff;
    request[6] = (stun::MAGIC_COOKIE >> 8) & 0xff;
    request[7] = stun::MAGIC_COOKIE & 0xff;
    std::memcpy(request + 8, txn_id.data(), 12);

    // Send request
    async_net::udp::endpoint remote_ep(port, server_ip.c_str());
    auto sent = co_await sock.async_send_to(
        async_net::const_buffer(request, sizeof(request)), remote_ep);
    if (sent <= 0) {
        co_return std::nullopt;
    }

    // Wait for response with timeout
    uint8_t response[1024];
    async_net::udp::endpoint sender_ep;
    auto received = co_await sock.async_receive_from(
        async_net::mutable_buffer(response, sizeof(response)), sender_ep);

    if (received < stun::HEADER_LEN) {
        co_return std::nullopt;
    }

    // Parse response
    co_return parse_response(response, received, stun::MAGIC_COOKIE);
}

async_net::Task<std::optional<stun_result>> stun_client::discover_any(
    std::chrono::milliseconds timeout) {

    auto servers = default_servers();
    for (const auto& [host, port] : servers) {
        auto result = co_await discover(host, port, timeout);
        if (result) {
            co_return result;
        }
    }
    co_return std::nullopt;
}

std::optional<stun_result> stun_client::parse_response(
    const uint8_t* data, size_t len, uint32_t magic_cookie) {

    if (len < stun::HEADER_LEN) return std::nullopt;

    // Check message type (should be Binding Response)
    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != stun::BINDING_RESPONSE) return std::nullopt;

    uint16_t msg_len = (data[2] << 8) | data[3];
    if (len < stun::HEADER_LEN + msg_len) return std::nullopt;

    stun_result result;
    result.nat = nat_type::unknown;

    // Parse attributes
    size_t offset = stun::HEADER_LEN;
    while (offset + 4 <= stun::HEADER_LEN + msg_len) {
        uint16_t attr_type = (data[offset] << 8) | data[offset + 1];
        uint16_t attr_len  = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;

        if (offset + attr_len > len) break;

        if (attr_type == stun::XOR_MAPPED_ADDRESS && attr_len >= 8) {
            uint8_t family = data[offset + 1];
            uint16_t xor_port = (data[offset + 2] << 8) | data[offset + 3];
            uint32_t xor_ip = (data[offset + 4] << 24) | (data[offset + 5] << 16) |
                              (data[offset + 6] << 8) | data[offset + 7];

            if (family == stun::AF_IPV4) {
                uint16_t port = xor_port ^ (magic_cookie >> 16);
                uint32_t ip = xor_ip ^ magic_cookie;

                char ip_str[INET_ADDRSTRLEN];
                uint32_t ip_bytes[4] = {
                    (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                    (ip >> 8) & 0xff, ip & 0xff
                };
                snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                         ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

                result.mapped_ip = ip_str;
                result.mapped_port = port;
            }
        } else if (attr_type == stun::MAPPED_ADDRESS && attr_len >= 8 && result.mapped_ip.empty()) {
            uint8_t family = data[offset + 1];
            uint16_t port = (data[offset + 2] << 8) | data[offset + 3];

            if (family == stun::AF_IPV4) {
                char ip_str[INET_ADDRSTRLEN];
                snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                         data[offset + 4], data[offset + 5],
                         data[offset + 6], data[offset + 7]);
                result.mapped_ip = ip_str;
                result.mapped_port = port;
            }
        }

        // Attributes are padded to 4-byte boundary
        offset += (attr_len + 3) & ~3;
    }

    if (result.mapped_ip.empty()) return std::nullopt;
    return result;
}

std::vector<std::pair<std::string, uint16_t>> stun_client::default_servers() {
    return {
        {"stun.l.google.com", 19302},
        {"stun1.l.google.com", 19302},
        {"stun2.l.google.com", 19302},
        {"stun3.l.google.com", 19302},
        {"stun4.l.google.com", 19302},
        {"stun.stunprotocol.org", 3478},
        {"stun.serverbreath.com", 3478},
    };
}

const char* nat_type_to_string(nat_type t) {
    switch (t) {
        case nat_type::open_internet:   return "Open Internet";
        case nat_type::full_cone:       return "Full Cone NAT";
        case nat_type::restricted_cone: return "Restricted Cone NAT";
        case nat_type::port_restricted: return "Port Restricted NAT";
        case nat_type::symmetric:       return "Symmetric NAT";
        case nat_type::blocked:         return "UDP Blocked";
        default:                        return "Unknown";
    }
}

} // namespace easytier::nat
