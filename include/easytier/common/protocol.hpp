#pragma once

#include "types.hpp"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>

namespace easytier {

/// Magic number for EasyTier protocol frames.
static constexpr uint16_t PROTOCOL_MAGIC = 0x4554;  // "ET"

/// Protocol version.
static constexpr uint8_t PROTOCOL_VERSION = 1;

/// Frame header size: magic(2) + version(1) + msg_type(1) + length(4) = 8 bytes.
static constexpr size_t FRAME_HEADER_SIZE = 8;

/// Message types for the EasyTier protocol.
enum class msg_type : uint8_t {
    // ---- Registry protocol (TCP) ----
    REGISTER      = 0x01,  ///< Client -> Server: Register this node
    REGISTER_ACK  = 0x02,  ///< Server -> Client: Registration acknowledged
    LIST_NODES    = 0x03,  ///< Client -> Server: Request node list
    NODE_LIST     = 0x04,  ///< Server -> Client: Node list response
    HEARTBEAT     = 0x05,  ///< Bidirectional: Keepalive
    HEARTBEAT_ACK = 0x06,  ///< Server -> Client: Heartbeat acknowledged
    NODE_JOINED   = 0x07,  ///< Server -> Client: A new node joined
    NODE_LEFT     = 0x08,  ///< Server -> Client: A node left

    // ---- P2P / Relay data protocol (UDP DTLS / TCP) ----
    DATA          = 0x10,  ///< Forwarded virtual network IP packet
    PING          = 0x11,  ///< NAT traversal probe / keepalive
    PONG          = 0x12,  ///< Response to PING
    HANDSHAKE     = 0x13,  ///< Connection handshake (exchange node info)
    HANDSHAKE_ACK = 0x14,  ///< Handshake acknowledged
    ROUTE_UPDATE  = 0x15,  ///< Route table update broadcast
    DISCONNECT    = 0x16,  ///< Graceful disconnect
};

/// Wire frame format:
///   [magic:2][version:1][msg_type:1][length:4][payload:N]
///
/// - magic:     0x4554 ("ET"), big-endian
/// - version:   Protocol version (currently 1)
/// - msg_type:  Message type
/// - length:    Payload length (big-endian uint32), NOT including header
/// - payload:   Variable-length payload
struct frame_header {
    uint16_t magic;
    uint8_t  version;
    uint8_t  type;
    uint32_t length;

    /// Serialize header to 8 bytes (big-endian).
    void serialize(uint8_t* buf) const {
        buf[0] = static_cast<uint8_t>((magic >> 8) & 0xFF);
        buf[1] = static_cast<uint8_t>( magic        & 0xFF);
        buf[2] = version;
        buf[3] = type;
        buf[4] = static_cast<uint8_t>((length >> 24) & 0xFF);
        buf[5] = static_cast<uint8_t>((length >> 16) & 0xFF);
        buf[6] = static_cast<uint8_t>((length >>  8) & 0xFF);
        buf[7] = static_cast<uint8_t>( length        & 0xFF);
    }

    /// Deserialize header from 8 bytes. Returns false if magic/version invalid.
    bool deserialize(const uint8_t* buf) {
        magic   = (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
        version = buf[2];
        type    = buf[3];
        length  = (static_cast<uint32_t>(buf[4]) << 24) |
                  (static_cast<uint32_t>(buf[5]) << 16) |
                  (static_cast<uint32_t>(buf[6]) <<  8) |
                   static_cast<uint32_t>(buf[7]);
        return magic == PROTOCOL_MAGIC && version == PROTOCOL_VERSION;
    }
};

/// A complete protocol frame (header + payload).
struct frame {
    msg_type type;
    std::vector<uint8_t> payload;

    /// Serialize the complete frame (header + payload) to bytes.
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(FRAME_HEADER_SIZE + payload.size());
        frame_header hdr;
        hdr.magic   = PROTOCOL_MAGIC;
        hdr.version = PROTOCOL_VERSION;
        hdr.type    = static_cast<uint8_t>(type);
        hdr.length  = static_cast<uint32_t>(payload.size());
        hdr.serialize(buf.data());
        if (!payload.empty()) {
            std::memcpy(buf.data() + FRAME_HEADER_SIZE, payload.data(), payload.size());
        }
        return buf;
    }

    /// Deserialize a frame from bytes. Returns nullopt if invalid.
    static std::optional<frame> deserialize(const uint8_t* data, size_t len) {
        if (len < FRAME_HEADER_SIZE) return std::nullopt;
        frame_header hdr;
        if (!hdr.deserialize(data)) return std::nullopt;
        if (len < FRAME_HEADER_SIZE + hdr.length) return std::nullopt;
        frame f;
        f.type = static_cast<msg_type>(hdr.type);
        f.payload.assign(data + FRAME_HEADER_SIZE,
                         data + FRAME_HEADER_SIZE + hdr.length);
        return f;
    }
};

// ============================================================
// Payload builders for specific message types
// ============================================================

namespace payload {

/// REGISTER payload: [node_id:8][udp_port:2][tcp_port:2][name_len:2][name:N]
struct register_payload {
    NodeId      node_id;
    uint16_t    udp_port;
    uint16_t    tcp_port;
    std::string name;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(14 + name.size());
        uint8_t* p = buf.data();
        // node_id (8 bytes, big-endian)
        NodeId nid = node_id;
        for (int i = 7; i >= 0; --i) { p[i] = static_cast<uint8_t>(nid & 0xFF); nid >>= 8; }
        p += 8;
        // udp_port (2 bytes, big-endian)
        p[0] = static_cast<uint8_t>((udp_port >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( udp_port        & 0xFF);
        p += 2;
        // tcp_port (2 bytes, big-endian)
        p[0] = static_cast<uint8_t>((tcp_port >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( tcp_port        & 0xFF);
        p += 2;
        // name_len (2 bytes) + name
        uint16_t name_len = static_cast<uint16_t>(name.size());
        p[0] = static_cast<uint8_t>((name_len >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( name_len        & 0xFF);
        if (name_len > 0) {
            std::memcpy(p + 2, name.data(), name_len);
        }
        return buf;
    }

    static std::optional<register_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 14) return std::nullopt;
        register_payload p;
        p.node_id = 0;
        for (int i = 0; i < 8; ++i) { p.node_id = (p.node_id << 8) | data[i]; }
        p.udp_port = (static_cast<uint16_t>(data[8]) << 8) | data[9];
        p.tcp_port = (static_cast<uint16_t>(data[10]) << 8) | data[11];
        uint16_t name_len = (static_cast<uint16_t>(data[12]) << 8) | data[13];
        if (len < 14 + name_len) return std::nullopt;
        p.name.assign(reinterpret_cast<const char*>(data + 14), name_len);
        return p;
    }
};

/// REGISTER_ACK payload: [node_id:8][virtual_ip:4]
struct register_ack_payload {
    NodeId    node_id;
    VirtualIP virtual_ip;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(12);
        NodeId nid = node_id;
        for (int i = 7; i >= 0; --i) { buf[i] = static_cast<uint8_t>(nid & 0xFF); nid >>= 8; }
        auto vip = reinterpret_cast<const uint8_t*>(&virtual_ip);
        std::memcpy(buf.data() + 8, vip, 4);
        return buf;
    }

    static std::optional<register_ack_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 12) return std::nullopt;
        register_ack_payload p;
        p.node_id = 0;
        for (int i = 0; i < 8; ++i) { p.node_id = (p.node_id << 8) | data[i]; }
        std::memcpy(&p.virtual_ip, data + 8, 4);
        return p;
    }
};

/// NODE_LIST payload: [count:2] { [node_id:8][virtual_ip:4][addr_len:2][addr:N][udp_port:2][tcp_port:2][name_len:2][name:N] } ...
struct node_entry {
    NodeId      node_id;
    VirtualIP   virtual_ip;
    std::string public_address;
    uint16_t    udp_port;
    uint16_t    tcp_port;
    std::string name;

    size_t serialized_size() const {
        return 8 + 4 + 2 + public_address.size() + 2 + 2 + 2 + name.size();
    }

    uint8_t* serialize_to(uint8_t* p) const {
        // node_id (8 bytes)
        NodeId nid = node_id;
        for (int i = 7; i >= 0; --i) { p[i] = static_cast<uint8_t>(nid & 0xFF); nid >>= 8; }
        p += 8;
        // virtual_ip (4 bytes)
        std::memcpy(p, &virtual_ip, 4);
        p += 4;
        // public_address
        uint16_t addr_len = static_cast<uint16_t>(public_address.size());
        p[0] = static_cast<uint8_t>((addr_len >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( addr_len        & 0xFF);
        p += 2;
        if (addr_len > 0) { std::memcpy(p, public_address.data(), addr_len); p += addr_len; }
        // udp_port
        p[0] = static_cast<uint8_t>((udp_port >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( udp_port        & 0xFF);
        p += 2;
        // tcp_port
        p[0] = static_cast<uint8_t>((tcp_port >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( tcp_port        & 0xFF);
        p += 2;
        // name
        uint16_t name_len = static_cast<uint16_t>(name.size());
        p[0] = static_cast<uint8_t>((name_len >> 8) & 0xFF);
        p[1] = static_cast<uint8_t>( name_len        & 0xFF);
        p += 2;
        if (name_len > 0) { std::memcpy(p, name.data(), name_len); p += name_len; }
        return p;
    }

    static std::optional<node_entry> deserialize_from(const uint8_t* data, size_t remaining) {
        if (remaining < 8 + 4 + 2) return std::nullopt;
        node_entry e;
        e.node_id = 0;
        for (int i = 0; i < 8; ++i) { e.node_id = (e.node_id << 8) | data[i]; }
        data += 8; remaining -= 8;
        std::memcpy(&e.virtual_ip, data, 4);
        data += 4; remaining -= 4;
        uint16_t addr_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2; remaining -= 2;
        if (remaining < addr_len + 4 + 2) return std::nullopt;
        e.public_address.assign(reinterpret_cast<const char*>(data), addr_len);
        data += addr_len; remaining -= addr_len;
        e.udp_port = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2; remaining -= 2;
        e.tcp_port = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2; remaining -= 2;
        if (remaining < 2) return std::nullopt;
        uint16_t name_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2; remaining -= 2;
        if (remaining < name_len) return std::nullopt;
        e.name.assign(reinterpret_cast<const char*>(data), name_len);
        return e;
    }
};

struct node_list_payload {
    std::vector<node_entry> nodes;

    std::vector<uint8_t> serialize() const {
        // Calculate total size
        size_t total = 2; // count
        for (const auto& n : nodes) total += n.serialized_size();
        std::vector<uint8_t> buf(total);
        uint16_t count = static_cast<uint16_t>(nodes.size());
        buf[0] = static_cast<uint8_t>((count >> 8) & 0xFF);
        buf[1] = static_cast<uint8_t>( count        & 0xFF);
        uint8_t* p = buf.data() + 2;
        for (const auto& n : nodes) {
            p = n.serialize_to(p);
        }
        return buf;
    }

    static std::optional<node_list_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 2) return std::nullopt;
        node_list_payload p;
        uint16_t count = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2; len -= 2;
        for (uint16_t i = 0; i < count; ++i) {
            auto entry = node_entry::deserialize_from(data, len);
            if (!entry) return std::nullopt;
            len -= entry->serialized_size();
            data += entry->serialized_size();
            p.nodes.push_back(std::move(*entry));
        }
        return p;
    }
};

/// HANDSHAKE payload: [node_id:8][virtual_ip:4]
struct handshake_payload {
    NodeId    node_id;
    VirtualIP virtual_ip;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(12);
        NodeId nid = node_id;
        for (int i = 7; i >= 0; --i) { buf[i] = static_cast<uint8_t>(nid & 0xFF); nid >>= 8; }
        std::memcpy(buf.data() + 8, &virtual_ip, 4);
        return buf;
    }

    static std::optional<handshake_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 12) return std::nullopt;
        handshake_payload p;
        p.node_id = 0;
        for (int i = 0; i < 8; ++i) { p.node_id = (p.node_id << 8) | data[i]; }
        std::memcpy(&p.virtual_ip, data + 8, 4);
        return p;
    }
};

/// DATA payload: [src_node_id:8][dst_virtual_ip:4][ip_packet:N]
struct data_payload {
    NodeId    src_node_id;
    VirtualIP dst_virtual_ip;
    std::vector<uint8_t> ip_packet;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(12 + ip_packet.size());
        NodeId nid = src_node_id;
        for (int i = 7; i >= 0; --i) { buf[i] = static_cast<uint8_t>(nid & 0xFF); nid >>= 8; }
        std::memcpy(buf.data() + 8, &dst_virtual_ip, 4);
        if (!ip_packet.empty()) {
            std::memcpy(buf.data() + 12, ip_packet.data(), ip_packet.size());
        }
        return buf;
    }

    static std::optional<data_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 12) return std::nullopt;
        data_payload p;
        p.src_node_id = 0;
        for (int i = 0; i < 8; ++i) { p.src_node_id = (p.src_node_id << 8) | data[i]; }
        std::memcpy(&p.dst_virtual_ip, data + 8, 4);
        p.ip_packet.assign(data + 12, data + len);
        return p;
    }
};

/// Route entry for ROUTE_UPDATE messages
struct route_entry_data {
    VirtualIP dst_vip;        // Destination virtual IP
    NodeId    via_node;       // Next hop node ID
    uint32_t  latency_ms;     // Latency in milliseconds
    uint8_t   hop_count;      // Number of hops

    size_t serialized_size() const { return 4 + 8 + 4 + 1; }

    uint8_t* serialize_to(uint8_t* p) const {
        std::memcpy(p, &dst_vip, 4); p += 4;
        NodeId nid = via_node;
        for (int i = 7; i >= 0; --i) { p[i] = static_cast<uint8_t>(nid & 0xFF); nid >>= 8; }
        p += 8;
        p[0] = static_cast<uint8_t>((latency_ms >> 24) & 0xFF);
        p[1] = static_cast<uint8_t>((latency_ms >> 16) & 0xFF);
        p[2] = static_cast<uint8_t>((latency_ms >>  8) & 0xFF);
        p[3] = static_cast<uint8_t>( latency_ms        & 0xFF);
        p += 4;
        p[0] = hop_count;
        p += 1;
        return p;
    }

    static std::optional<route_entry_data> deserialize_from(const uint8_t* data, size_t remaining) {
        if (remaining < 17) return std::nullopt;
        route_entry_data e;
        std::memcpy(&e.dst_vip, data, 4); data += 4; remaining -= 4;
        e.via_node = 0;
        for (int i = 0; i < 8; ++i) { e.via_node = (e.via_node << 8) | data[i]; }
        data += 8; remaining -= 8;
        e.latency_ms = (static_cast<uint32_t>(data[0]) << 24) |
                       (static_cast<uint32_t>(data[1]) << 16) |
                       (static_cast<uint32_t>(data[2]) <<  8) |
                        static_cast<uint32_t>(data[3]);
        data += 4; remaining -= 4;
        e.hop_count = data[0];
        return e;
    }
};

/// ROUTE_UPDATE payload: [count:2] { route_entry_data } ...
struct route_update_payload {
    std::vector<route_entry_data> entries;

    std::vector<uint8_t> serialize() const {
        size_t total = 2;
        for (const auto& e : entries) total += e.serialized_size();
        std::vector<uint8_t> buf(total);
        uint16_t count = static_cast<uint16_t>(entries.size());
        buf[0] = static_cast<uint8_t>((count >> 8) & 0xFF);
        buf[1] = static_cast<uint8_t>( count        & 0xFF);
        uint8_t* p = buf.data() + 2;
        for (const auto& e : entries) {
            p = e.serialize_to(p);
        }
        return buf;
    }

    static std::optional<route_update_payload> deserialize(const uint8_t* data, size_t len) {
        if (len < 2) return std::nullopt;
        route_update_payload p;
        uint16_t count = (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2; len -= 2;
        for (uint16_t i = 0; i < count; ++i) {
            auto entry = route_entry_data::deserialize_from(data, len);
            if (!entry) return std::nullopt;
            len -= entry->serialized_size();
            data += entry->serialized_size();
            p.entries.push_back(std::move(*entry));
        }
        return p;
    }
};

} // namespace payload

// ============================================================
// Helper: build complete frames with payload
// ============================================================

inline frame make_register_frame(NodeId node_id, uint16_t udp_port,
                                  uint16_t tcp_port, const std::string& name) {
    payload::register_payload p{node_id, udp_port, tcp_port, name};
    return frame{msg_type::REGISTER, p.serialize()};
}

inline frame make_register_ack_frame(NodeId node_id, VirtualIP vip) {
    payload::register_ack_payload p{node_id, vip};
    return frame{msg_type::REGISTER_ACK, p.serialize()};
}

inline frame make_heartbeat_frame() {
    return frame{msg_type::HEARTBEAT, {}};
}

inline frame make_heartbeat_ack_frame() {
    return frame{msg_type::HEARTBEAT_ACK, {}};
}

inline frame make_list_nodes_frame() {
    return frame{msg_type::LIST_NODES, {}};
}

inline frame make_data_frame(NodeId src, VirtualIP dst, const uint8_t* pkt, size_t len) {
    payload::data_payload p{src, dst, std::vector<uint8_t>(pkt, pkt + len)};
    return frame{msg_type::DATA, p.serialize()};
}

inline frame make_ping_frame() {
    return frame{msg_type::PING, {}};
}

inline frame make_pong_frame() {
    return frame{msg_type::PONG, {}};
}

inline frame make_handshake_frame(NodeId node_id, VirtualIP vip) {
    payload::handshake_payload p{node_id, vip};
    return frame{msg_type::HANDSHAKE, p.serialize()};
}

inline frame make_handshake_ack_frame(NodeId node_id, VirtualIP vip) {
    payload::handshake_payload p{node_id, vip};
    return frame{msg_type::HANDSHAKE_ACK, p.serialize()};
}

inline frame make_disconnect_frame() {
    return frame{msg_type::DISCONNECT, {}};
}

} // namespace easytier
