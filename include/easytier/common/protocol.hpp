#pragma once

/// @file protocol.hpp
/// Protocol definitions compatible with Rust EasyTier.
///
/// Wire format:
///   TCP: [TCPTunnelHeader:4][PeerManagerHeader:12][Payload:N]
///   UDP: [UDPTunnelHeader:8][PeerManagerHeader:12][Payload:N]
///
/// All integer fields are little-endian.
/// Encryption: AES-128-GCM with AeadTail [tag:16][nonce:12] appended to payload.

#include "zc_packet.hpp"
#include "network_identity.hpp"
#include "types.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>

namespace easytier {

// ============================================================
// Handshake request — compatible with Rust HandshakeRequest protobuf
// ============================================================

namespace handshake {

/// Initial handshake sent over raw TCP/UDP before Noise negotiation.
/// Wire format: [magic:4][version:4][network_name_len:2][network_name:N][secret_digest:32]
struct handshake_hello {
    uint32_t magic = EASYTIER_MAGIC;
    uint32_t version = EASYTIER_VERSION;
    std::string network_name;
    network_digest_t secret_digest{};

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(8 + 2 + network_name.size() + 32);
        uint8_t* p = buf.data();
        // magic (LE)
        p[0] = static_cast<uint8_t>(magic);
        p[1] = static_cast<uint8_t>(magic >> 8);
        p[2] = static_cast<uint8_t>(magic >> 16);
        p[3] = static_cast<uint8_t>(magic >> 24);
        p += 4;
        // version (LE)
        p[0] = static_cast<uint8_t>(version);
        p[1] = static_cast<uint8_t>(version >> 8);
        p[2] = static_cast<uint8_t>(version >> 16);
        p[3] = static_cast<uint8_t>(version >> 24);
        p += 4;
        // network_name_len (LE)
        uint16_t name_len = static_cast<uint16_t>(network_name.size());
        p[0] = static_cast<uint8_t>(name_len);
        p[1] = static_cast<uint8_t>(name_len >> 8);
        p += 2;
        // network_name
        if (name_len > 0) {
            std::memcpy(p, network_name.data(), name_len);
            p += name_len;
        }
        // secret_digest (32 bytes)
        std::memcpy(p, secret_digest.data(), 32);
        return buf;
    }

    static std::optional<handshake_hello> deserialize(const uint8_t* data, size_t len) {
        if (len < 10) return std::nullopt;
        handshake_hello h;
        // magic (LE)
        h.magic = static_cast<uint32_t>(data[0])
                | (static_cast<uint32_t>(data[1]) << 8)
                | (static_cast<uint32_t>(data[2]) << 16)
                | (static_cast<uint32_t>(data[3]) << 24);
        if (h.magic != EASYTIER_MAGIC) return std::nullopt;
        data += 4; len -= 4;
        // version (LE)
        h.version = static_cast<uint32_t>(data[0])
                  | (static_cast<uint32_t>(data[1]) << 8)
                  | (static_cast<uint32_t>(data[2]) << 16)
                  | (static_cast<uint32_t>(data[3]) << 24);
        data += 4; len -= 4;
        // network_name_len (LE)
        if (len < 2) return std::nullopt;
        uint16_t name_len = static_cast<uint16_t>(data[0])
                          | (static_cast<uint16_t>(data[1]) << 8);
        data += 2; len -= 2;
        if (len < name_len + 32) return std::nullopt;
        h.network_name.assign(reinterpret_cast<const char*>(data), name_len);
        data += name_len; len -= name_len;
        // secret_digest
        std::memcpy(h.secret_digest.data(), data, 32);
        return h;
    }
};

} // namespace handshake

// ============================================================
// Noise handshake payload builders
// ============================================================

namespace noise_payload {

/// Noise Msg1: version + network_name + conn_id + encryption_algorithm
/// Serialized as protobuf PeerConnNoiseMsg1Pb when EASYTIER_HAS_PROTOBUF is defined.
/// Otherwise, simple binary format for basic compatibility.
struct msg1 {
    uint32_t version = EASYTIER_VERSION;
    std::string network_name;
    uint32_t session_generation = 0;
    uint8_t conn_id[16]{};  // UUID as 16 bytes
    std::string encryption_algorithm = "aes-gcm";

    std::vector<uint8_t> serialize() const;
    static std::optional<msg1> deserialize(const uint8_t* data, size_t len);
};

/// Noise Msg2: network_name + role_hint + action + conn_ids + encryption_algorithm
struct msg2 {
    std::string network_name;
    uint32_t role_hint = 0;
    uint8_t action = 0;  // 0=Join, 1=Sync, 2=Create
    uint32_t session_generation = 0;
    uint8_t b_conn_id[16]{};
    uint8_t a_conn_id_echo[16]{};
    std::string encryption_algorithm = "aes-gcm";

    std::vector<uint8_t> serialize() const;
    static std::optional<msg2> deserialize(const uint8_t* data, size_t len);
};

/// Noise Msg3: conn_id echoes + secret_digest
struct msg3 {
    uint8_t a_conn_id_echo[16]{};
    uint8_t b_conn_id_echo[16]{};
    network_digest_t secret_digest{};

    std::vector<uint8_t> serialize() const;
    static std::optional<msg3> deserialize(const uint8_t* data, size_t len);
};

} // namespace noise_payload

// ============================================================
// Legacy type aliases for backward compatibility during migration
// ============================================================

// NodeId and PeerId are defined in types.hpp
// Old VirtualIP type remains uint32_t (also in types.hpp)

// ============================================================
// NAT type — compatible with Rust NatType enum
// ============================================================

enum class nat_type : uint8_t {
    Unknown            = 0,
    OpenInternet       = 1,
    NoPAT              = 2,
    FullCone           = 3,
    Restricted         = 4,
    PortRestricted     = 5,
    Symmetric          = 6,
    SymUdpFirewall     = 7,
    SymmetricEasyInc   = 8,
    SymmetricEasyDec   = 9,
};

// ============================================================
// Peer feature flags — compatible with Rust PeerFeatureFlag
// ============================================================

struct peer_feature_flag {
    bool is_public_server = false;
    bool avoid_relay_data = false;
    bool kcp_input = false;
    bool no_relay_kcp = false;
    bool support_conn_list_sync = false;
    bool quic_input = false;
    bool no_relay_quic = false;
    bool is_credential_peer = false;
    bool need_p2p = false;
    bool disable_p2p = false;
    bool ipv6_public_addr_provider = false;
};

} // namespace easytier

// ============================================================
// Legacy internal frame types — used by registry_client, peer_manager,
// router, and relay_transport for the internal (C++-to-C++) protocol.
// These are NOT wire-compatible with Rust EasyTier; the ZCPacket types
// above are used for Rust interop.
// ============================================================

namespace easytier {

static constexpr size_t FRAME_HEADER_SIZE = 12;

/// Internal message types for C++ registry/peer communication.
enum class msg_type : uint8_t {
    // Peer messages
    PING            = 1,
    PONG            = 2,
    DATA            = 3,
    HANDSHAKE       = 4,
    HANDSHAKE_ACK   = 5,
    // Registry messages
    REGISTER        = 20,
    REGISTER_ACK    = 21,
    HEARTBEAT       = 22,
    HEARTBEAT_ACK   = 23,
    NODE_LIST       = 24,
    LIST_NODES      = 24,  // alias for NODE_LIST
    NODE_JOINED     = 25,
    NODE_LEFT       = 26,
    ROUTE_UPDATE    = 30,
    DISCONNECT      = 40,
};

/// Internal frame header (12 bytes on wire).
/// Wire format: [magic:2][version:1][type:1][reserved:2][length:4(le)]
#pragma pack(push, 1)
struct frame_header_raw {
    uint16_t magic;
    uint8_t  version;
    uint8_t  type;
    uint32_t reserved;
    uint32_t length;
};
#pragma pack(pop)
static_assert(sizeof(frame_header_raw) == FRAME_HEADER_SIZE);

/// Parsed frame header with convenience methods.
struct frame_header {
    uint8_t  type = 0;
    uint32_t length = 0;

    bool deserialize(const uint8_t* data) {
        auto* raw = reinterpret_cast<const frame_header_raw*>(data);
        if (raw->magic != 0x4554) return false;
        type = raw->type;
        length = raw->length;
        return true;
    }

    void serialize(uint8_t* data) const {
        auto* raw = reinterpret_cast<frame_header_raw*>(data);
        raw->magic = 0x4554;
        raw->version = 1;
        raw->type = type;
        raw->reserved = 0;
        raw->length = length;
    }
};

/// Internal frame: type + payload bytes.
struct frame {
    msg_type type = msg_type::PING;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(FRAME_HEADER_SIZE + payload.size());
        frame_header hdr;
        hdr.type = static_cast<uint8_t>(type);
        hdr.length = static_cast<uint32_t>(payload.size());
        hdr.serialize(buf.data());
        if (!payload.empty()) {
            std::memcpy(buf.data() + FRAME_HEADER_SIZE, payload.data(), payload.size());
        }
        return buf;
    }

    static std::optional<frame> deserialize(const uint8_t* data, size_t len) {
        if (len < FRAME_HEADER_SIZE) return std::nullopt;
        frame_header hdr;
        if (!hdr.deserialize(data)) return std::nullopt;
        frame f;
        f.type = static_cast<msg_type>(hdr.type);
        if (hdr.length > 0 && len >= FRAME_HEADER_SIZE + hdr.length) {
            f.payload.assign(data + FRAME_HEADER_SIZE,
                             data + FRAME_HEADER_SIZE + hdr.length);
        }
        return f;
    }
};

// ============================================================
// Internal payload serializers (for C++-to-C++ protocol)
// ============================================================

namespace payload {

// Helper: write uint32 LE
inline void write_u32(uint8_t* p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v>>8)&0xFF; p[2] = (v>>16)&0xFF; p[3] = (v>>24)&0xFF;
}
inline uint32_t read_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
inline void write_u64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (v >> (i*8)) & 0xFF;
}
inline uint64_t read_u64(const uint8_t* p) {
    uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (i*8); return v;
}

// --- handshake_payload ---
struct handshake_payload {
    NodeId    node_id = 0;
    VirtualIP virtual_ip = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(8);
        write_u32(buf.data(), node_id);
        write_u32(buf.data()+4, virtual_ip);
        return buf;
    }
    static std::optional<handshake_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 8) return std::nullopt;
        handshake_payload h;
        h.node_id = read_u32(data);
        h.virtual_ip = read_u32(data+4);
        return h;
    }
};

// --- data_payload ---
struct data_payload {
    NodeId    src_node_id = 0;
    VirtualIP dst_virtual_ip = 0;
    std::vector<uint8_t> ip_packet;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(8 + ip_packet.size());
        write_u32(buf.data(), src_node_id);
        write_u32(buf.data()+4, dst_virtual_ip);
        if (!ip_packet.empty())
            std::memcpy(buf.data()+8, ip_packet.data(), ip_packet.size());
        return buf;
    }
    static std::optional<data_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 8) return std::nullopt;
        data_payload d;
        d.src_node_id = read_u32(data);
        d.dst_virtual_ip = read_u32(data+4);
        if (len > 8) d.ip_packet.assign(data+8, data+len);
        return d;
    }
};

// --- register_payload ---
struct register_payload {
    NodeId      node_id = 0;
    uint16_t    udp_port = 0;
    uint16_t    tcp_port = 0;
    std::string name;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(12 + name.size());
        write_u32(buf.data(), node_id);
        buf[4] = udp_port & 0xFF; buf[5] = (udp_port>>8)&0xFF;
        buf[6] = tcp_port & 0xFF; buf[7] = (tcp_port>>8)&0xFF;
        // bytes 8-11: name length
        write_u32(buf.data()+8, static_cast<uint32_t>(name.size()));
        // Note: name follows after 12 bytes
        // Actually let's simplify: fixed 12 byte header + name
        buf.resize(12 + name.size());
        std::memcpy(buf.data()+12, name.data(), name.size());
        return buf;
    }
    static std::optional<register_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 12) return std::nullopt;
        register_payload r;
        r.node_id = read_u32(data);
        r.udp_port = (uint16_t)data[4] | ((uint16_t)data[5]<<8);
        r.tcp_port = (uint16_t)data[6] | ((uint16_t)data[7]<<8);
        uint32_t name_len = read_u32(data+8);
        if (len < 12 + name_len) return std::nullopt;
        r.name.assign(reinterpret_cast<const char*>(data+12), name_len);
        return r;
    }
};

// --- register_ack_payload ---
struct register_ack_payload {
    NodeId    node_id = 0;
    VirtualIP virtual_ip = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(8);
        write_u32(buf.data(), node_id);
        write_u32(buf.data()+4, virtual_ip);
        return buf;
    }
    static std::optional<register_ack_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 8) return std::nullopt;
        register_ack_payload r;
        r.node_id = read_u32(data);
        r.virtual_ip = read_u32(data+4);
        return r;
    }
};

// --- node_entry ---
struct node_entry {
    NodeId      node_id = 0;
    VirtualIP   virtual_ip = 0;
    std::string public_address;
    uint16_t    udp_port = 0;
    uint16_t    tcp_port = 0;
    std::string name;

    std::vector<uint8_t> serialize() const {
        auto buf = serialize_internal();
        return buf;
    }

    size_t serialized_size() const {
        return serialize_internal().size();
    }

    void serialize_to(uint8_t* out) const {
        auto buf = serialize_internal();
        std::memcpy(out, buf.data(), buf.size());
    }

private:
    std::vector<uint8_t> serialize_internal() const {
        // [node_id:4][vip:4][udp:2][tcp:2][addr_len:2][addr:N][name_len:2][name:N]
        size_t total = 14 + public_address.size() + name.size();
        std::vector<uint8_t> buf(total);
        uint8_t* p = buf.data();
        write_u32(p, node_id); p += 4;
        write_u32(p, virtual_ip); p += 4;
        p[0] = udp_port & 0xFF; p[1] = (udp_port>>8)&0xFF; p += 2;
        p[0] = tcp_port & 0xFF; p[1] = (tcp_port>>8)&0xFF; p += 2;
        uint16_t alen = static_cast<uint16_t>(public_address.size());
        p[0] = alen & 0xFF; p[1] = (alen>>8)&0xFF; p += 2;
        if (alen > 0) { std::memcpy(p, public_address.data(), alen); p += alen; }
        uint16_t nlen = static_cast<uint16_t>(name.size());
        p[0] = nlen & 0xFF; p[1] = (nlen>>8)&0xFF; p += 2;
        if (nlen > 0) std::memcpy(p, name.data(), nlen);
        return buf;
    }

public:
    static std::optional<node_entry> deserialize_from(const uint8_t* data, size_t len) {
        if (len < 14) return std::nullopt;
        node_entry e;
        e.node_id = read_u32(data); data += 4; len -= 4;
        e.virtual_ip = read_u32(data); data += 4; len -= 4;
        e.udp_port = (uint16_t)data[0] | ((uint16_t)data[1]<<8); data += 2; len -= 2;
        e.tcp_port = (uint16_t)data[0] | ((uint16_t)data[1]<<8); data += 2; len -= 2;
        if (len < 2) return std::nullopt;
        uint16_t alen = (uint16_t)data[0] | ((uint16_t)data[1]<<8); data += 2; len -= 2;
        if (len < alen) return std::nullopt;
        e.public_address.assign(reinterpret_cast<const char*>(data), alen); data += alen; len -= alen;
        if (len < 2) return std::nullopt;
        uint16_t nlen = (uint16_t)data[0] | ((uint16_t)data[1]<<8); data += 2; len -= 2;
        if (len < nlen) return std::nullopt;
        e.name.assign(reinterpret_cast<const char*>(data), nlen);
        return e;
    }
};

// --- node_list_payload ---
struct node_list_payload {
    std::vector<node_entry> nodes;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        uint32_t count = static_cast<uint32_t>(nodes.size());
        buf.resize(4);
        write_u32(buf.data(), count);
        for (const auto& n : nodes) {
            auto nd = n.serialize();
            // Prepend entry size
            uint32_t esize = static_cast<uint32_t>(nd.size());
            uint8_t sz[4]; write_u32(sz, esize);
            buf.insert(buf.end(), sz, sz+4);
            buf.insert(buf.end(), nd.begin(), nd.end());
        }
        return buf;
    }
    static std::optional<node_list_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 4) return std::nullopt;
        node_list_payload nl;
        uint32_t count = read_u32(data); data += 4; len -= 4;
        for (uint32_t i = 0; i < count; ++i) {
            if (len < 4) return std::nullopt;
            uint32_t esize = read_u32(data); data += 4; len -= 4;
            if (len < esize) return std::nullopt;
            auto e = node_entry::deserialize_from(data, esize);
            if (e) nl.nodes.push_back(*e);
            data += esize; len -= esize;
        }
        return nl;
    }
};

// --- route_entry_data ---
struct route_entry_data {
    VirtualIP dst_vip = 0;
    NodeId    via_node = 0;
    uint32_t  latency_ms = 0;
    uint8_t   hop_count = 1;
};

// --- route_update_payload ---
struct route_update_payload {
    std::vector<route_entry_data> entries;

    std::vector<uint8_t> serialize() const {
        // [count:4] then [dst:4][via:4][lat:4][hop:1] per entry
        std::vector<uint8_t> buf(4 + entries.size() * 13);
        write_u32(buf.data(), static_cast<uint32_t>(entries.size()));
        uint8_t* p = buf.data() + 4;
        for (const auto& e : entries) {
            write_u32(p, e.dst_vip); p += 4;
            write_u32(p, e.via_node); p += 4;
            write_u32(p, e.latency_ms); p += 4;
            p[0] = e.hop_count; p += 1;
        }
        return buf;
    }
    static std::optional<route_update_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 4) return std::nullopt;
        route_update_payload u;
        uint32_t count = read_u32(data); data += 4; len -= 4;
        for (uint32_t i = 0; i < count && len >= 13; ++i) {
            route_entry_data e;
            e.dst_vip = read_u32(data); data += 4;
            e.via_node = read_u32(data); data += 4;
            e.latency_ms = read_u32(data); data += 4;
            e.hop_count = data[0]; data += 1;
            len -= 13;
            u.entries.push_back(e);
        }
        return u;
    }
};

} // namespace payload

// ============================================================
// Frame factory functions
// ============================================================

inline frame make_ping_frame() {
    return frame{msg_type::PING, {}};
}

inline frame make_pong_frame() {
    return frame{msg_type::PONG, {}};
}

inline frame make_handshake_frame(NodeId nid, VirtualIP vip) {
    payload::handshake_payload h{nid, vip};
    return frame{msg_type::HANDSHAKE, h.serialize()};
}

inline frame make_handshake_ack_frame(NodeId nid, VirtualIP vip) {
    payload::handshake_payload h{nid, vip};
    return frame{msg_type::HANDSHAKE_ACK, h.serialize()};
}

inline frame make_data_frame(NodeId src, VirtualIP dst, const uint8_t* data, size_t len) {
    payload::data_payload d;
    d.src_node_id = src;
    d.dst_virtual_ip = dst;
    d.ip_packet.assign(data, data + len);
    return frame{msg_type::DATA, d.serialize()};
}

inline frame make_register_frame(NodeId nid, uint16_t udp_port, uint16_t tcp_port,
                                  const std::string& name) {
    payload::register_payload r{nid, udp_port, tcp_port, name};
    return frame{msg_type::REGISTER, r.serialize()};
}

inline frame make_heartbeat_frame() {
    return frame{msg_type::HEARTBEAT, {}};
}

inline frame make_list_nodes_frame() {
    return frame{msg_type::NODE_LIST, {}};
}

inline frame make_disconnect_frame() {
    return frame{msg_type::DISCONNECT, {}};
}

inline frame make_heartbeat_ack_frame() {
    return frame{msg_type::HEARTBEAT_ACK, {}};
}

inline frame make_register_ack_frame(NodeId nid, VirtualIP vip) {
    payload::register_ack_payload r{nid, vip};
    return frame{msg_type::REGISTER_ACK, r.serialize()};
}

} // namespace easytier
