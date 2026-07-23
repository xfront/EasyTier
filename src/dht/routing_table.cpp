#include "easytier/dht/routing_table.hpp"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace easytier::dht {

// node_id implementation
node_id node_id::from_bytes(const uint8_t* data, size_t len) {
    node_id id;
    size_t copy_len = std::min(len, size_t(20));
    std::memcpy(id.bytes.data(), data, copy_len);
    return id;
}

node_id node_id::from_uint64(uint64_t val) {
    node_id id;
    for (int i = 0; i < 8; ++i) {
        id.bytes[i] = (val >> (56 - i * 8)) & 0xff;
    }
    return id;
}

uint64_t node_id::to_uint64() const {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return val;
}

node_id node_id::from_hex(const std::string& hex) {
    node_id id;
    if (hex.size() < 40) return id;
    for (int i = 0; i < 20; ++i) {
        id.bytes[i] = std::stoi(hex.substr(i * 2, 2), nullptr, 16);
    }
    return id;
}

std::string node_id::to_hex() const {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

node_id xor_distance(const node_id& a, const node_id& b) {
    node_id result;
    for (int i = 0; i < 20; ++i) {
        result.bytes[i] = a.bytes[i] ^ b.bytes[i];
    }
    return result;
}

int bucket_index(const node_id& distance) {
    for (int i = 0; i < 20; ++i) {
        if (distance.bytes[i] != 0) {
            // Find the highest set bit in this byte
            uint8_t b = distance.bytes[i];
            int bit = 7;
            while (bit >= 0 && !(b & (1 << bit))) --bit;
            return (19 - i) * 8 + bit;
        }
    }
    return 0;  // Same node
}

// k_bucket implementation
bool k_bucket::add_node(const node_info& node) {
    // Check if node already exists
    for (auto& n : nodes) {
        if (n.id == node.id) {
            n = node;  // Update
            n.last_seen = std::chrono::steady_clock::now();
            return true;
        }
    }

    // Add if not full
    if (nodes.size() < K) {
        nodes.push_back(node);
        nodes.back().last_seen = std::chrono::steady_clock::now();
        return true;
    }

    return false;  // Bucket full
}

void k_bucket::remove_node(const node_id& id) {
    nodes.erase(std::remove_if(nodes.begin(), nodes.end(),
                               [&id](const node_info& n) { return n.id == id; }),
                nodes.end());
}

bool k_bucket::contains(const node_id& id) const {
    return std::any_of(nodes.begin(), nodes.end(),
                       [&id](const node_info& n) { return n.id == id; });
}

std::optional<node_info> k_bucket::least_recently_seen() const {
    if (nodes.empty()) return std::nullopt;
    return *std::min_element(nodes.begin(), nodes.end(),
                             [](const node_info& a, const node_info& b) {
                                 return a.last_seen < b.last_seen;
                             });
}

// routing_table implementation
routing_table::routing_table(const node_id& my_id) : my_id_(my_id) {
    auto now = std::chrono::steady_clock::now();
    for (int i = 0; i < NUM_BUCKETS; ++i) {
        last_refresh_[i] = now;
    }
}

bool routing_table::add_node(const node_info& node) {
    if (node.id == my_id_) return false;

    auto dist = xor_distance(my_id_, node.id);
    int idx = bucket_index(dist);

    if (idx < 0 || idx >= NUM_BUCKETS) return false;

    bool added = buckets_[idx].add_node(node);
    if (added) {
        last_refresh_[idx] = std::chrono::steady_clock::now();
    }
    return added;
}

void routing_table::remove_node(const node_id& id) {
    auto dist = xor_distance(my_id_, id);
    int idx = bucket_index(dist);
    if (idx >= 0 && idx < NUM_BUCKETS) {
        buckets_[idx].remove_node(id);
    }
}

std::vector<node_info> routing_table::find_nearest(const node_id& target, int k) const {
    std::vector<node_info> all;
    for (const auto& bucket : buckets_) {
        for (const auto& node : bucket.all_nodes()) {
            if (node.is_alive()) {
                all.push_back(node);
            }
        }
    }

    // Sort by XOR distance to target
    std::sort(all.begin(), all.end(),
              [&target](const node_info& a, const node_info& b) {
                  auto da = xor_distance(a.id, target);
                  auto db = xor_distance(b.id, target);
                  return da < db;
              });

    if ((int)all.size() > k) {
        all.resize(k);
    }
    return all;
}

std::optional<node_info> routing_table::get_node(const node_id& id) const {
    auto dist = xor_distance(my_id_, id);
    int idx = bucket_index(dist);
    if (idx < 0 || idx >= NUM_BUCKETS) return std::nullopt;

    for (const auto& node : buckets_[idx].all_nodes()) {
        if (node.id == id) return node;
    }
    return std::nullopt;
}

size_t routing_table::size() const {
    size_t count = 0;
    for (const auto& bucket : buckets_) {
        count += bucket.all_nodes().size();
    }
    return count;
}

size_t routing_table::bucket_count() const {
    size_t count = 0;
    for (const auto& bucket : buckets_) {
        if (!bucket.all_nodes().empty()) ++count;
    }
    return count;
}

std::vector<node_info> routing_table::all_nodes() const {
    std::vector<node_info> all;
    for (const auto& bucket : buckets_) {
        for (const auto& node : bucket.all_nodes()) {
            all.push_back(node);
        }
    }
    return all;
}

std::vector<node_id> routing_table::buckets_to_refresh(std::chrono::minutes max_age) const {
    std::vector<node_id> targets;
    auto now = std::chrono::steady_clock::now();

    for (int i = 0; i < NUM_BUCKETS; ++i) {
        if (now - last_refresh_[i] > max_age) {
            // Generate a random ID in this bucket's range
            node_id target = my_id_;
            target.bytes[19 - i / 8] ^= (1 << (i % 8));
            targets.push_back(target);
        }
    }
    return targets;
}

} // namespace easytier::dht
