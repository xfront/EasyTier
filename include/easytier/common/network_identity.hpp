#pragma once

#include <string>
#include <cstdint>
#include <array>
#include <optional>

namespace easytier {

/// Network secret digest: 32 bytes, computed from network_name + network_secret
/// using SipHash-2-4 compatible with Rust's DefaultHasher.
using network_digest_t = std::array<uint8_t, 32>;

/// Generate a 32-byte digest from two strings, compatible with Rust's
/// std::collections::hash_map::DefaultHasher (SipHash-2-4).
network_digest_t generate_digest_from_str(const std::string& str1, const std::string& str2);

/// Network identity: name + optional secret
struct network_identity {
    std::string network_name;
    std::optional<std::string> network_secret;
    std::optional<network_digest_t> secret_digest;

    /// Compute digest from name + secret if secret is provided
    void compute_digest() {
        if (network_secret.has_value()) {
            secret_digest = generate_digest_from_str(network_name, *network_secret);
        }
    }

    /// Compare with another identity (by digest if available, else by name)
    bool matches(const network_identity& other) const {
        if (secret_digest.has_value() && other.secret_digest.has_value()) {
            return network_name == other.network_name &&
                   *secret_digest == *other.secret_digest;
        }
        return network_name == other.network_name;
    }
};

/// SipHash-2-4 implementation compatible with Rust's DefaultHasher
class sip_hasher {
public:
    sip_hasher();

    void write(const uint8_t* data, size_t len);
    void write(const std::string& s) { write(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

    uint64_t finish();

private:
    uint64_t k0, k1;
    uint64_t v0, v1, v2, v3;
    uint64_t total_len;
    uint8_t buf[8];
    size_t buf_len;

    void sip_round();
    void process_block(uint64_t m);
};

} // namespace easytier
