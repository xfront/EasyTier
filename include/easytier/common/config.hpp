#pragma once

#include "types.hpp"
#include "network_identity.hpp"
#include <string>
#include <cstdint>
#include <chrono>
#include <vector>

namespace easytier {

/// Configuration for an EasyTier node.
struct node_config {
    /// This node's unique ID (0 = auto-generate).
    /// Now PeerId (u32), compatible with Rust EasyTier.
    PeerId my_peer_id = 0;

    /// Human-readable name for this node.
    std::string name = "easytier-node";

    /// Hostname for this device.
    std::string hostname;

    // === Network Identity (Rust-compatible) ===
    /// Network name used to identify this VPN network.
    std::string network_name = "default";

    /// Network secret for authentication.
    std::string network_secret;

    /// Computed network secret digest (32 bytes).
    network_digest_t secret_digest{};

    // === Connection ===
    /// Registry server address.
    std::string registry_host = "127.0.0.1";

    /// Registry server port.
    uint16_t registry_port = 11010;

    /// Initial peer addresses to connect to.
    std::vector<std::string> peers;

    /// Listener URLs (e.g. "tcp://0.0.0.0:11010", "udp://0.0.0.0:11010").
    std::vector<std::string> listeners;

    /// Local UDP port for P2P connections (0 = auto).
    uint16_t udp_port = 0;

    /// Local TCP port for relay connections (0 = auto).
    uint16_t tcp_port = 0;

    /// Virtual IPv4 address (empty = DHCP/auto-assign).
    std::string ipv4;

    /// Virtual network CIDR base (e.g. "10.10.0.0").
    std::string network_cidr = "10.10.0.0";

    /// Network mask bits (e.g. 16 for /16).
    int network_mask = 16;

    /// TUN device name (empty = auto-assign, e.g. "et0").
    std::string tun_name = "";

    /// MTU for the TUN device.
    int mtu = 1380;

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

    /// Disable IPv6 entirely.
    bool disable_ipv6 = false;

    // === Security ===
    /// Ed25519 private key file (empty = auto-generate).
    std::string private_key_file;

    /// Pre-shared key for simple deployment.
    std::string psk;

    /// Enable encryption for peer communication.
    bool enable_encryption = true;

    /// Encryption algorithm: "aes-gcm" (default), "aes-gcm-256", "chacha20", "xor".
    std::string encryption_algorithm = "aes-gcm";

    // === Routing ===
    /// Latency-first mode (use lowest latency path instead of shortest).
    bool latency_first = false;

    /// Enable exit node functionality.
    bool enable_exit_node = false;

    /// Don't create TUN device.
    bool no_tun = false;

    // === DHT ===
    /// Bootstrap nodes for DHT network (format: "ip:port").
    std::vector<std::string> bootstrap_nodes;

    /// Enable DHT mode (decentralized, replaces registry).
    bool enable_dht = false;

    // === Web API ===
    /// Web API / RPC portal port (0 = disabled).
    uint16_t web_api_port = 15888;

    /// Enable web API server.
    bool enable_web_api = true;

    // === Subnet Proxy ===
    /// Subnets to proxy (e.g. "192.168.1.0/24").
    std::vector<std::string> proxy_subnets;

    // === KCP / QUIC proxy ===
    /// Enable KCP proxy for TCP streams.
    bool enable_kcp_proxy = false;

    /// Allow KCP input from other nodes.
    bool disable_kcp_input = false;

    /// Enable QUIC proxy for TCP streams.
    bool enable_quic_proxy = false;

    /// Allow QUIC input from other nodes.
    bool disable_quic_input = false;

    // === P2P ===
    /// Disable P2P connections.
    bool disable_p2p = false;

    /// Only communicate with P2P-connected peers.
    bool p2p_only = false;

    /// Default protocol for connecting to peers.
    std::string default_protocol = "tcp";

    /// Compute network secret digest from name + secret.
    void compute_network_identity() {
        if (!network_secret.empty()) {
            secret_digest = generate_digest_from_str(network_name, network_secret);
        }
    }
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
