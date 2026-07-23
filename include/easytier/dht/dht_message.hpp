#pragma once

#include "routing_table.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>

namespace easytier::dht {

/// DHT message types (Kademlia protocol).
enum class dht_msg_type : uint8_t {
    ping              = 1,
    pong              = 2,
    find_node         = 3,
    find_node_response = 4,
    register_value    = 5,
    register_ack      = 6,
    find_value        = 7,
    find_value_response = 8,
};

/// Base DHT message header.
struct dht_header {
    uint8_t      magic = 0xED;      ///< Magic byte for EasyTier DHT
    uint8_t      version = 1;
    dht_msg_type type;
    uint32_t     length = 0;        ///< Total message length
    node_id      sender_id;
    uint16_t     transaction_id = 0;

    static constexpr size_t SIZE = 1 + 1 + 1 + 4 + 20 + 2;  // 29 bytes
};

/// PING message — check if a node is alive.
struct ping_message {
    dht_header header;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(dht_header::SIZE);
        data[0] = header.magic;
        data[1] = header.version;
        data[2] = static_cast<uint8_t>(header.type);
        data[3] = 0; data[4] = 0; data[5] = 0; data[6] = dht_header::SIZE;
        std::memcpy(data.data() + 7, header.sender_id.bytes.data(), 20);
        data[27] = (header.transaction_id >> 8) & 0xff;
        data[28] = header.transaction_id & 0xff;
        return data;
    }
};

/// FIND_NODE message — find K nearest nodes to a target ID.
struct find_node_message {
    dht_header header;
    node_id    target_id;
    uint16_t   k = 20;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(dht_header::SIZE + 20 + 2);
        data[0] = header.magic;
        data[1] = header.version;
        data[2] = static_cast<uint8_t>(header.type);
        uint32_t len = data.size();
        data[3] = (len >> 24) & 0xff;
        data[4] = (len >> 16) & 0xff;
        data[5] = (len >> 8) & 0xff;
        data[6] = len & 0xff;
        std::memcpy(data.data() + 7, header.sender_id.bytes.data(), 20);
        data[27] = (header.transaction_id >> 8) & 0xff;
        data[28] = header.transaction_id & 0xff;
        std::memcpy(data.data() + 29, target_id.bytes.data(), 20);
        data[49] = (k >> 8) & 0xff;
        data[50] = k & 0xff;
        return data;
    }

    static find_node_message deserialize(const uint8_t* data, size_t len) {
        find_node_message msg;
        if (len < dht_header::SIZE + 22) return msg;
        msg.header.type = static_cast<dht_msg_type>(data[2]);
        std::memcpy(msg.header.sender_id.bytes.data(), data + 7, 20);
        msg.header.transaction_id = (data[27] << 8) | data[28];
        std::memcpy(msg.target_id.bytes.data(), data + 29, 20);
        msg.k = (data[49] << 8) | data[50];
        return msg;
    }
};

/// FIND_NODE_RESPONSE — contains K nearest nodes.
struct find_node_response_message {
    dht_header header;
    std::vector<node_info> nodes;

    std::vector<uint8_t> serialize() const {
        // Each node: [id:20][ip_len:1][ip:N][udp_port:2][tcp_port:2]
        std::vector<uint8_t> data;
        data.reserve(dht_header::SIZE + nodes.size() * 50);

        // Header placeholder
        data.resize(dht_header::SIZE, 0);

        // Nodes
        for (const auto& node : nodes) {
            // Node ID
            data.insert(data.end(), node.id.bytes.begin(), node.id.bytes.end());
            // IP
            data.push_back(static_cast<uint8_t>(node.ip.size()));
            data.insert(data.end(), node.ip.begin(), node.ip.end());
            // Ports
            data.push_back((node.udp_port >> 8) & 0xff);
            data.push_back(node.udp_port & 0xff);
            data.push_back((node.tcp_port >> 8) & 0xff);
            data.push_back(node.tcp_port & 0xff);
        }

        // Update header
        data[0] = header.magic;
        data[1] = header.version;
        data[2] = static_cast<uint8_t>(header.type);
        uint32_t len = data.size();
        data[3] = (len >> 24) & 0xff;
        data[4] = (len >> 16) & 0xff;
        data[5] = (len >> 8) & 0xff;
        data[6] = len & 0xff;
        std::memcpy(data.data() + 7, header.sender_id.bytes.data(), 20);
        data[27] = (header.transaction_id >> 8) & 0xff;
        data[28] = header.transaction_id & 0xff;

        return data;
    }

    static find_node_response_message deserialize(const uint8_t* data, size_t len) {
        find_node_response_message msg;
        if (len < dht_header::SIZE) return msg;

        msg.header.type = static_cast<dht_msg_type>(data[2]);
        std::memcpy(msg.header.sender_id.bytes.data(), data + 7, 20);
        msg.header.transaction_id = (data[27] << 8) | data[28];

        size_t offset = dht_header::SIZE;
        while (offset + 25 <= len) {  // Minimum: id(20) + ip_len(1) + port(4)
            node_info node;
            std::memcpy(node.id.bytes.data(), data + offset, 20);
            offset += 20;

            uint8_t ip_len = data[offset++];
            if (offset + ip_len + 4 > len) break;
            node.ip.assign(reinterpret_cast<const char*>(data + offset), ip_len);
            offset += ip_len;

            node.udp_port = (data[offset] << 8) | data[offset + 1];
            node.tcp_port = (data[offset + 2] << 8) | data[offset + 3];
            offset += 4;

            msg.nodes.push_back(node);
        }

        return msg;
    }
};

/// REGISTER_VALUE — register a virtual IP to node mapping.
struct register_value_message {
    dht_header header;
    node_id    key;           ///< Key (e.g., hash of virtual IP)
    node_id    value_node_id; ///< Node ID that owns this VIP
    std::string value_ip;     ///< Virtual IP address
    uint32_t   ttl = 3600;    ///< Time to live in seconds

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.reserve(128);
        data.resize(dht_header::SIZE, 0);

        // Key
        data.insert(data.end(), key.bytes.begin(), key.bytes.end());
        // Value node ID
        data.insert(data.end(), value_node_id.bytes.begin(), value_node_id.bytes.end());
        // Value IP
        data.push_back(static_cast<uint8_t>(value_ip.size()));
        data.insert(data.end(), value_ip.begin(), value_ip.end());
        // TTL
        data.push_back((ttl >> 24) & 0xff);
        data.push_back((ttl >> 16) & 0xff);
        data.push_back((ttl >> 8) & 0xff);
        data.push_back(ttl & 0xff);

        // Update header
        data[0] = header.magic;
        data[1] = header.version;
        data[2] = static_cast<uint8_t>(header.type);
        uint32_t len = data.size();
        data[3] = (len >> 24) & 0xff;
        data[4] = (len >> 16) & 0xff;
        data[5] = (len >> 8) & 0xff;
        data[6] = len & 0xff;
        std::memcpy(data.data() + 7, header.sender_id.bytes.data(), 20);
        data[27] = (header.transaction_id >> 8) & 0xff;
        data[28] = header.transaction_id & 0xff;

        return data;
    }
};

/// Parse a DHT message from raw bytes.
inline dht_msg_type parse_message_type(const uint8_t* data, size_t len) {
    if (len < 3 || data[0] != 0xED) return static_cast<dht_msg_type>(0);
    return static_cast<dht_msg_type>(data[2]);
}

} // namespace easytier::dht
