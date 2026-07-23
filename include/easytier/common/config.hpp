#pragma once

#include "types.hpp"
#include <string>
#include <cstdint>
#include <chrono>
#include <vector>

namespace easytier {

/// Configuration for an EasyTier node.
struct node_config {
    /// This node's unique ID (0 = auto-generate).
    NodeId node_id = 0;

    /// Human-readable name for this node.
    std::string name = "easytier-node";

    /// Registry server address.
    std::string registry_host = "127.0.0.1";

    /// Registry server port.
    uint16_t registry_port = 11010;

    /// Local UDP port for P2P connections (0 = auto).
    uint16_t udp_port = 0;

    /// Local TCP port for relay connections (0 = auto).
    uint16_t tcp_port = 0;

    /// Virtual network CIDR base (e.g. "10.10.0.0").
    std::string network_cidr = "10.10.0.0";

    /// Network mask bits (e.g. 16 for /16).
    int network_mask = 16;

    /// TUN device name (empty = auto-assign, e.g. "et0").
    std::string tun_name = "";

    /// MTU for the TUN device.
    int mtu = 1400;

    /// Certificate file for DTLS.
    std::string cert_file = "server_cert.pem";

    /// Private key file for DTLS.
    std::string key_file = "server_key.pem";

    /// Heartbeat interval to registry (seconds).
    std::chrono::seconds registry_heartbeat_interval{30};

    /// Peer keepalive interval (seconds).
    std::chrono::seconds peer_keepalive_interval{10};

    /// P2P connection timeout (seconds).
    std::chrono::seconds p2p_connect_timeout{5};

    // === NAT Traversal ===
    /// STUN server list for NAT discovery.
    std::vector<std::string> stun_servers;

    /// Enable IPv6 support.
    bool enable_ipv6 = true;

    // === Security ===
    /// Ed25519 private key file (empty = auto-generate).
    std::string private_key_file;

    /// Pre-shared key for simple deployment.
    std::string psk;

    /// Enable encryption for peer communication.
    bool enable_encryption = true;

    // === DHT ===
    /// Bootstrap nodes for DHT network (format: "ip:port").
    std::vector<std::string> bootstrap_nodes;

    /// Enable DHT mode (decentralized, replaces registry).
    bool enable_dht = false;

    // === Web API ===
    /// Web API listen port (0 = disabled).
    uint16_t web_api_port = 11080;

    /// Enable web API server.
    bool enable_web_api = true;

    // === Subnet Proxy ===
    /// Subnets to proxy (e.g. "192.168.1.0/24").
    std::vector<std::string> proxy_subnets;
};

/// Configuration for the registry server.
struct registry_config {
    /// Listen port.
    uint16_t port = 11010;

    /// Virtual network CIDR base.
    std::string network_cidr = "10.10.0.0";

    /// Network mask bits.
    int network_mask = 16;

    /// Peer timeout (peers not seen within this duration are removed).
    std::chrono::seconds peer_timeout{90};
};

} // namespace easytier
