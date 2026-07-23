#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <chrono>
#include <optional>

namespace easytier::dht {

/// 160-bit node ID for Kademlia DHT (SHA-1 hash space).
struct node_id {
    std::array<uint8_t, 20> bytes{};

    bool operator==(const node_id& other) const { return bytes == other.bytes; }
    bool operator!=(const node_id& other) const { return bytes != other.bytes; }
    bool operator<(const node_id& other) const { return bytes < other.bytes; }

    /// Create node_id from raw bytes.
    static node_id from_bytes(const uint8_t* data, size_t len);

    /// Create node_id from a 64-bit value (for compatibility with NodeId).
    static node_id from_uint64(uint64_t id);

    /// Convert to 64-bit value (first 8 bytes).
    uint64_t to_uint64() const;

    /// Create from hex string.
    static node_id from_hex(const std::string& hex);

    /// Convert to hex string.
    std::string to_hex() const;
};

/// XOR distance between two node IDs.
node_id xor_distance(const node_id& a, const node_id& b);

/// Get the bucket index for a given XOR distance (0-159).
int bucket_index(const node_id& distance);

/// Information about a node in the DHT.
struct node_info {
    node_id     id;
    std::string ip;
    uint16_t    udp_port = 0;
    uint16_t    tcp_port = 0;
    std::chrono::steady_clock::time_point last_seen;
    uint32_t    fail_count = 0;

    bool is_alive() const {
        auto age = std::chrono::steady_clock::now() - last_seen;
        return age < std::chrono::minutes(15) && fail_count < 3;
    }
};

/// K-bucket for storing nodes at a specific distance range.
/// Each bucket holds up to K nodes (default K=20).
struct k_bucket {
    static constexpr int K = 20;

    std::vector<node_info> nodes;

    /// Add or update a node in the bucket.
    /// Returns true if the node was added/updated, false if bucket is full.
    bool add_node(const node_info& node);

    /// Remove a node by ID.
    void remove_node(const node_id& id);

    /// Check if bucket contains a node.
    bool contains(const node_id& id) const;

    /// Get the least recently seen node (for eviction).
    std::optional<node_info> least_recently_seen() const;

    /// Check if bucket is full.
    bool is_full() const { return nodes.size() >= K; }

    /// Get all nodes in the bucket.
    const std::vector<node_info>& all_nodes() const { return nodes; }
};

/// Kademlia routing table — 160 k-buckets organized by XOR distance.
///
/// Bucket i contains nodes with XOR distance in [2^i, 2^(i+1)).
/// Each bucket holds up to K=20 nodes.
///
/// Usage:
///   routing_table table(my_node_id);
///   table.add_node(some_node);
///   auto nearest = table.find_nearest(target_id, 20);
class routing_table {
public:
    static constexpr int NUM_BUCKETS = 160;

    explicit routing_table(const node_id& my_id);

    /// Add or update a node in the routing table.
    /// Returns true if the node was added/updated.
    bool add_node(const node_info& node);

    /// Remove a node by ID.
    void remove_node(const node_id& id);

    /// Find the K nearest nodes to a target ID (by XOR distance).
    std::vector<node_info> find_nearest(const node_id& target, int k = 20) const;

    /// Get a node by ID.
    std::optional<node_info> get_node(const node_id& id) const;

    /// Get the total number of nodes in the table.
    size_t size() const;

    /// Get the number of non-empty buckets.
    size_t bucket_count() const;

    /// Get all nodes in the routing table.
    std::vector<node_info> all_nodes() const;

    /// Get nodes that need refreshing (buckets not updated recently).
    std::vector<node_id> buckets_to_refresh(std::chrono::minutes max_age = std::chrono::minutes(10)) const;

    /// Get my node ID.
    const node_id& my_id() const { return my_id_; }

private:
    node_id my_id_;
    std::array<k_bucket, NUM_BUCKETS> buckets_;
    std::chrono::steady_clock::time_point last_refresh_[NUM_BUCKETS];
};

} // namespace easytier::dht
