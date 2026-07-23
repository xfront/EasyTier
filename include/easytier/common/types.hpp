#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <cstdio>

namespace easytier {

/// Unique identifier for each node in the virtual network.
using NodeId = uint64_t;

/// Virtual IP address (IPv4, stored as uint32_t in network byte order).
using VirtualIP = uint32_t;

/// Transport type for peer connections.
enum class transport_type : uint8_t {
    p2p   = 0,   ///< Direct P2P connection (UDP hole punching + DTLS)
    relay = 1,   ///< Relay through intermediate node (TCP)
    ws    = 2,   ///< WebSocket transport (ws:// or wss://)
    quic  = 3,   ///< QUIC transport (HTTP/3)
    kcp   = 4,   ///< KCP reliable UDP transport
};

/// Connection state of a peer.
enum class connection_state : uint8_t {
    connecting   = 0,
    connected    = 1,
    disconnected = 2,
};

/// Information about a remote node (from registry).
struct node_info {
    NodeId      node_id = 0;
    VirtualIP   virtual_ip = 0;
    std::string public_address;   ///< Public IP observed by registry
    uint16_t    udp_port = 0;     ///< UDP listening port for P2P
    uint16_t    tcp_port = 0;     ///< TCP listening port for relay
    std::string name;             ///< Human-readable name

    /// Returns "ip:port" string for the UDP endpoint.
    std::string udp_endpoint_str() const {
        return public_address + ":" + std::to_string(udp_port);
    }

    /// Returns "ip:port" string for the TCP endpoint.
    std::string tcp_endpoint_str() const {
        return public_address + ":" + std::to_string(tcp_port);
    }
};

/// Convert VirtualIP (network byte order uint32) to "a.b.c.d" string.
inline std::string virtual_ip_to_string(VirtualIP ip) {
    auto bytes = reinterpret_cast<const uint8_t*>(&ip);
    return std::to_string(bytes[0]) + "." +
           std::to_string(bytes[1]) + "." +
           std::to_string(bytes[2]) + "." +
           std::to_string(bytes[3]);
}

/// Convert "a.b.c.d" string to VirtualIP (network byte order uint32).
inline VirtualIP string_to_virtual_ip(const std::string& s) {
    uint32_t a, b, c, d;
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    VirtualIP ip;
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&ip);
    bytes[0] = static_cast<uint8_t>(a);
    bytes[1] = static_cast<uint8_t>(b);
    bytes[2] = static_cast<uint8_t>(c);
    bytes[3] = static_cast<uint8_t>(d);
    return ip;
}

/// Generate a random NodeId.
inline NodeId generate_node_id() {
    static uint64_t counter = 0;
    // Use a combination of time-based and counter-based approach
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<NodeId>(now ^ (++counter * 6364136223846793005ULL));
}

} // namespace easytier
