#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <optional>
#include <span>
#include <algorithm>

namespace easytier {

// ============================================================
// Wire format constants — aligned with Rust EasyTier
// ============================================================

static constexpr size_t TCP_TUNNEL_HEADER_SIZE = 4;
static constexpr size_t UDP_TUNNEL_HEADER_SIZE = 8;
static constexpr size_t WG_TUNNEL_HEADER_SIZE  = 20;
static constexpr size_t PEER_MANAGER_HEADER_SIZE = 16;
static constexpr size_t AEAD_TAG_SIZE  = 16;
static constexpr size_t AEAD_NONCE_SIZE = 12;
static constexpr size_t AEAD_TAIL_SIZE = AEAD_TAG_SIZE + AEAD_NONCE_SIZE; // 28

// ============================================================
// Packet type enum — must match Rust PacketType exactly
// ============================================================

enum class packet_type : uint8_t {
    Invalid                    = 0,
    Data                       = 1,
    HandShake                  = 2,
    // RoutePacket (3) deprecated
    Ping                       = 4,
    Pong                       = 5,
    // TaRpc (6) deprecated
    // Route (7) deprecated
    RpcReq                     = 8,
    RpcResp                    = 9,
    ForeignNetworkPacket       = 10,
    KcpSrc                     = 11,
    KcpDst                     = 12,
    NoiseHandshakeMsg1         = 13,
    NoiseHandshakeMsg2         = 14,
    NoiseHandshakeMsg3         = 15,
    QuicSrc                    = 16,
    QuicDst                    = 17,
    // DataWithKcpSrcModified (18), DataWithQuicSrcModified (19) internal only
    RelayHandshake             = 20,
    RelayHandshakeAck          = 21,
};

// ============================================================
// PeerManagerHeader flags
// ============================================================

namespace pm_flags {
    static constexpr uint8_t ENCRYPTED      = 0x01;
    static constexpr uint8_t LATENCY_FIRST  = 0x02;
    static constexpr uint8_t EXIT_NODE      = 0x04;
    static constexpr uint8_t NO_PROXY       = 0x08;
    static constexpr uint8_t COMPRESSED     = 0x10;
    static constexpr uint8_t NOT_SEND_TO_TUN = 0x40;
}

// ============================================================
// Wire structures — all fields little-endian, packed
// ============================================================

#pragma pack(push, 1)

/// TCP tunnel header: 4 bytes
struct tcp_tunnel_header {
    uint32_t len; // little-endian

    uint32_t get_len() const { return len; }
    void set_len(uint32_t v) { len = v; }
};

/// UDP tunnel header: 8 bytes
struct udp_tunnel_header {
    uint32_t conn_id;   // little-endian
    uint8_t  msg_type;
    uint8_t  padding;
    uint16_t len;       // little-endian

    uint32_t get_conn_id() const { return conn_id; }
    uint16_t get_len() const { return len; }
};

/// WireGuard tunnel header: 20 bytes (fake IPv4 header)
struct wg_tunnel_header {
    uint8_t ipv4_header[20];
};

/// PeerManager header: 12 bytes — the core header for all EasyTier packets
struct peer_manager_header {
    uint32_t from_peer_id;      // LE
    uint32_t to_peer_id;        // LE
    uint8_t  pkt_type;
    uint8_t  flags;
    uint8_t  forward_counter;
    uint8_t  reserved;
    uint32_t len;               // LE, payload length

    uint32_t get_from_peer_id() const { return from_peer_id; }
    uint32_t get_to_peer_id() const { return to_peer_id; }
    void set_from_peer_id(uint32_t v) { from_peer_id = v; }
    void set_to_peer_id(uint32_t v) { to_peer_id = v; }

    packet_type get_packet_type() const { return static_cast<packet_type>(pkt_type); }
    void set_packet_type(packet_type t) { pkt_type = static_cast<uint8_t>(t); }

    uint32_t get_len() const { return len; }
    void set_len(uint32_t v) { len = v; }

    bool is_encrypted() const { return (flags & pm_flags::ENCRYPTED) != 0; }
    void set_encrypted(bool v) {
        if (v) flags |= pm_flags::ENCRYPTED;
        else   flags &= ~pm_flags::ENCRYPTED;
    }

    bool is_latency_first() const { return (flags & pm_flags::LATENCY_FIRST) != 0; }
    void set_latency_first(bool v) {
        if (v) flags |= pm_flags::LATENCY_FIRST;
        else   flags &= ~pm_flags::LATENCY_FIRST;
    }

    bool is_exit_node() const { return (flags & pm_flags::EXIT_NODE) != 0; }
    void set_exit_node(bool v) {
        if (v) flags |= pm_flags::EXIT_NODE;
        else   flags &= ~pm_flags::EXIT_NODE;
    }

    bool is_compressed() const { return (flags & pm_flags::COMPRESSED) != 0; }
    void set_compressed(bool v) {
        if (v) flags |= pm_flags::COMPRESSED;
        else   flags &= ~pm_flags::COMPRESSED;
    }
};

/// AEAD tail appended after encrypted payload: [tag:16][nonce:12]
struct aead_tail {
    uint8_t tag[AEAD_TAG_SIZE];
    uint8_t nonce[AEAD_NONCE_SIZE];
};

/// Foreign network packet header
struct foreign_network_header {
    uint16_t header_len;          // LE
    uint32_t dst_peer_id;         // LE
    uint16_t network_name_offset; // LE
    uint16_t network_name_len;    // LE
};

#pragma pack(pop)

static_assert(sizeof(tcp_tunnel_header) == TCP_TUNNEL_HEADER_SIZE, "tcp_tunnel_header size mismatch");
static_assert(sizeof(udp_tunnel_header) == UDP_TUNNEL_HEADER_SIZE, "udp_tunnel_header size mismatch");
static_assert(sizeof(wg_tunnel_header) == WG_TUNNEL_HEADER_SIZE, "wg_tunnel_header size mismatch");
static_assert(sizeof(peer_manager_header) == PEER_MANAGER_HEADER_SIZE, "peer_manager_header size mismatch");
static_assert(sizeof(aead_tail) == AEAD_TAIL_SIZE, "aead_tail size mismatch");

// ============================================================
// ZCPacket type — which tunnel layer is present
// ============================================================

enum class zc_packet_type {
    TCP,         // received from TCP connection
    UDP,         // received from UDP connection
    WG,          // received from WireGuard connection
    NIC,         // from local TUN device
    DummyTunnel, // no tunnel header
};

// ============================================================
// ZCPacket — zero-copy layered packet
// ============================================================

class zc_packet {
public:
    /// Create a new packet from NIC (TUN) with payload
    static zc_packet new_with_payload(const uint8_t* payload, size_t len) {
        zc_packet pkt;
        pkt.type_ = zc_packet_type::NIC;
        size_t off = payload_offset(pkt.type_);
        pkt.buf_.resize(off + len);
        if (len > 0) std::memcpy(pkt.buf_.data() + off, payload, len);
        // Initialize PM header
        auto* pm = pkt.peer_manager_header_ptr();
        if (pm) {
            std::memset(pm, 0, PEER_MANAGER_HEADER_SIZE);
            pm->forward_counter = 1;
        }
        return pkt;
    }

    /// Create from raw buffer (received from network)
    static zc_packet from_buffer(std::vector<uint8_t> buf, zc_packet_type type) {
        zc_packet pkt;
        pkt.type_ = type;
        pkt.buf_ = std::move(buf);
        return pkt;
    }

    /// Create empty packet for TCP sending
    static zc_packet new_tcp(uint32_t from_peer, uint32_t to_peer, packet_type ptype, size_t payload_cap) {
        zc_packet pkt;
        pkt.type_ = zc_packet_type::TCP;
        size_t total = TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE + payload_cap;
        pkt.buf_.resize(total, 0);
        auto* tcp_hdr = pkt.tcp_tunnel_header_ptr();
        auto* pm_hdr = pkt.peer_manager_header_ptr();
        if (tcp_hdr) tcp_hdr->set_len(0); // will be updated on send
        if (pm_hdr) {
            std::memset(pm_hdr, 0, PEER_MANAGER_HEADER_SIZE);
            pm_hdr->set_from_peer_id(from_peer);
            pm_hdr->set_to_peer_id(to_peer);
            pm_hdr->set_packet_type(ptype);
            pm_hdr->forward_counter = 1;
        }
        return pkt;
    }

    /// Create empty packet for UDP sending
    static zc_packet new_udp(uint32_t from_peer, uint32_t to_peer, packet_type ptype,
                              uint32_t conn_id, size_t payload_cap) {
        zc_packet pkt;
        pkt.type_ = zc_packet_type::UDP;
        size_t total = UDP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE + payload_cap;
        pkt.buf_.resize(total, 0);
        auto* udp_hdr = pkt.udp_tunnel_header_ptr();
        auto* pm_hdr = pkt.peer_manager_header_ptr();
        if (udp_hdr) {
            std::memset(udp_hdr, 0, UDP_TUNNEL_HEADER_SIZE);
            udp_hdr->conn_id = conn_id;
        }
        if (pm_hdr) {
            std::memset(pm_hdr, 0, PEER_MANAGER_HEADER_SIZE);
            pm_hdr->set_from_peer_id(from_peer);
            pm_hdr->set_to_peer_id(to_peer);
            pm_hdr->set_packet_type(ptype);
            pm_hdr->forward_counter = 1;
        }
        return pkt;
    }

    // --- Accessors ---

    zc_packet_type type() const { return type_; }

    const peer_manager_header* pm_header() const {
        return const_cast<zc_packet*>(this)->peer_manager_header_ptr();
    }

    peer_manager_header* mutable_pm_header() {
        return peer_manager_header_ptr();
    }

    const tcp_tunnel_header* tcp_header() const {
        return const_cast<zc_packet*>(this)->tcp_tunnel_header_ptr();
    }

    const udp_tunnel_header* udp_header() const {
        return const_cast<zc_packet*>(this)->udp_tunnel_header_ptr();
    }

    /// Payload data (after tunnel header + PM header)
    std::span<const uint8_t> payload() const {
        size_t off = payload_offset(type_);
        if (buf_.size() < off) return {};
        return {buf_.data() + off, buf_.size() - off};
    }

    std::span<uint8_t> mutable_payload() {
        size_t off = payload_offset(type_);
        if (buf_.size() < off) return {};
        return {buf_.data() + off, buf_.size() - off};
    }

    size_t payload_len() const {
        size_t off = payload_offset(type_);
        return buf_.size() > off ? buf_.size() - off : 0;
    }

    /// Tunnel payload (PM header + payload, for relay)
    std::span<const uint8_t> tunnel_payload() const {
        size_t off = pm_offset(type_);
        if (buf_.size() < off) return {};
        return {buf_.data() + off, buf_.size() - off};
    }

    /// Fill PM header fields
    void fill_peer_manager_hdr(uint32_t from, uint32_t to, packet_type ptype) {
        auto* pm = peer_manager_header_ptr();
        if (!pm) return;
        pm->set_from_peer_id(from);
        pm->set_to_peer_id(to);
        pm->set_packet_type(ptype);
        pm->flags = 0;
        pm->forward_counter = 1;
        pm->set_len(static_cast<uint32_t>(payload_len()));
    }

    /// Update PM header len field to match current payload size
    void update_pm_len() {
        auto* pm = peer_manager_header_ptr();
        if (pm) pm->set_len(static_cast<uint32_t>(payload_len()));
    }

    /// Update TCP tunnel header len
    void update_tcp_len() {
        auto* tcp = tcp_tunnel_header_ptr();
        if (tcp) tcp->set_len(static_cast<uint32_t>(payload_len()));
    }

    /// Get raw buffer for sending
    const std::vector<uint8_t>& buffer() const { return buf_; }
    std::vector<uint8_t>& mutable_buffer() { return buf_; }

    /// Convert packet type (for sending via different transports)
    void convert_to(zc_packet_type target) {
        if (target == type_) return;
        // Extract PM header + payload
        size_t pm_off = pm_offset(type_);
        std::vector<uint8_t> pm_and_payload;
        if (pm_off < buf_.size()) {
            pm_and_payload.assign(buf_.begin() + pm_off, buf_.end());
        }
        // Build new buffer with target tunnel header
        size_t new_pm_off = pm_offset(target);
        buf_.resize(new_pm_off + pm_and_payload.size());
        std::memcpy(buf_.data() + new_pm_off, pm_and_payload.data(), pm_and_payload.size());
        // Zero the tunnel header area
        std::memset(buf_.data(), 0, new_pm_off);
        type_ = target;
    }

    /// Get peer IDs
    uint32_t src_peer_id() const {
        auto* pm = pm_header();
        return pm ? pm->get_from_peer_id() : 0;
    }

    uint32_t dst_peer_id() const {
        auto* pm = pm_header();
        return pm ? pm->get_to_peer_id() : 0;
    }

private:
    zc_packet_type type_ = zc_packet_type::DummyTunnel;
    std::vector<uint8_t> buf_;

    static size_t pm_offset(zc_packet_type t) {
        switch (t) {
            case zc_packet_type::TCP: return TCP_TUNNEL_HEADER_SIZE;
            case zc_packet_type::UDP: return UDP_TUNNEL_HEADER_SIZE;
            case zc_packet_type::WG:  return WG_TUNNEL_HEADER_SIZE;
            case zc_packet_type::DummyTunnel: return 0;
            case zc_packet_type::NIC: {
                // NIC reserves space for the largest tunnel header
                return std::max({TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE, WG_TUNNEL_HEADER_SIZE});
            }
        }
        return 0;
    }

    static size_t payload_offset(zc_packet_type t) {
        return pm_offset(t) + PEER_MANAGER_HEADER_SIZE;
    }

    peer_manager_header* peer_manager_header_ptr() {
        size_t off = pm_offset(type_);
        if (buf_.size() < off + PEER_MANAGER_HEADER_SIZE) return nullptr;
        return reinterpret_cast<peer_manager_header*>(buf_.data() + off);
    }

    tcp_tunnel_header* tcp_tunnel_header_ptr() {
        if (type_ != zc_packet_type::TCP) {
            // For NIC packets, we can access TCP header if there's enough space
            size_t off = pm_offset(type_);
            if (off < TCP_TUNNEL_HEADER_SIZE) return nullptr;
            size_t tcp_off = off - TCP_TUNNEL_HEADER_SIZE;
            if (buf_.size() < tcp_off + TCP_TUNNEL_HEADER_SIZE) return nullptr;
            return reinterpret_cast<tcp_tunnel_header*>(buf_.data() + tcp_off);
        }
        if (buf_.size() < TCP_TUNNEL_HEADER_SIZE) return nullptr;
        return reinterpret_cast<tcp_tunnel_header*>(buf_.data());
    }

    udp_tunnel_header* udp_tunnel_header_ptr() {
        if (type_ != zc_packet_type::UDP) {
            size_t off = pm_offset(type_);
            if (off < UDP_TUNNEL_HEADER_SIZE) return nullptr;
            size_t udp_off = off - UDP_TUNNEL_HEADER_SIZE;
            if (buf_.size() < udp_off + UDP_TUNNEL_HEADER_SIZE) return nullptr;
            return reinterpret_cast<udp_tunnel_header*>(buf_.data() + udp_off);
        }
        if (buf_.size() < UDP_TUNNEL_HEADER_SIZE) return nullptr;
        return reinterpret_cast<udp_tunnel_header*>(buf_.data());
    }
};

// ============================================================
// Magic number for initial handshake (pre-Noise)
// ============================================================

static constexpr uint32_t EASYTIER_MAGIC = 0xd1e1a5e1;
static constexpr uint32_t EASYTIER_VERSION = 1;

} // namespace easytier
