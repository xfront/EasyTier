#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>
#include <optional>

namespace easytier::crypto {

/// X25519 key exchange for establishing shared secrets between peers.
///
/// Each node generates an X25519 key pair:
/// - Private key: 32 bytes random
/// - Public key: 32 bytes (curve point)
///
/// Node ID is derived from the public key (first 8 bytes of SHA-256 hash).
///
/// Key exchange protocol:
/// 1. Alice sends Bob her public key (32 bytes)
/// 2. Bob sends Alice his public key (32 bytes)
/// 3. Both compute shared secret = X25519(private, peer_public)
/// 4. Derive session key using HKDF-SHA256
///
/// This implementation uses a simplified X25519 based on Curve25519 math.
/// For production, consider using libsodium or OpenSSL's X25519.
class key_exchange {
public:
    static constexpr size_t PRIVATE_KEY_LEN = 32;
    static constexpr size_t PUBLIC_KEY_LEN = 32;
    static constexpr size_t SHARED_SECRET_LEN = 32;

    /// Generate a new random private key.
    static std::vector<uint8_t> generate_private_key();

    /// Compute public key from private key (X25519 base point multiplication).
    static std::vector<uint8_t> compute_public_key(const uint8_t private_key[PRIVATE_KEY_LEN]);

    /// Compute shared secret from private key and peer's public key.
    /// Returns 32-byte shared secret.
    static std::vector<uint8_t> compute_shared_secret(
        const uint8_t private_key[PRIVATE_KEY_LEN],
        const uint8_t peer_public[PUBLIC_KEY_LEN]);

    /// Derive node ID from public key (first 8 bytes of SHA-256 hash).
    static uint64_t derive_node_id(const uint8_t public_key[PUBLIC_KEY_LEN]);

    /// Key exchange result containing shared secret and derived session key.
    struct exchange_result {
        std::vector<uint8_t> shared_secret;  // 32 bytes
        std::vector<uint8_t> session_key;    // 32 bytes (derived via HKDF)
        uint64_t peer_node_id;               // Peer's node ID
    };

    /// Perform key exchange: compute shared secret and derive session key.
    /// @param my_private My private key (32 bytes)
    /// @param peer_public Peer's public key (32 bytes)
    /// @param salt Optional salt for HKDF (can be empty)
    /// @param info Optional info string for HKDF
    static exchange_result perform_exchange(
        const uint8_t my_private[PRIVATE_KEY_LEN],
        const uint8_t peer_public[PUBLIC_KEY_LEN],
        const uint8_t* salt = nullptr, size_t salt_len = 0,
        const char* info = "easytier-session", size_t info_len = 17);
};

/// Key pair for a node (private + public keys).
class key_pair {
public:
    /// Generate a new random key pair.
    key_pair();

    /// Construct from existing private key.
    explicit key_pair(const std::vector<uint8_t>& private_key);

    /// Get the private key.
    const std::vector<uint8_t>& private_key() const { return private_key_; }

    /// Get the public key.
    const std::vector<uint8_t>& public_key() const { return public_key_; }

    /// Get the node ID derived from public key.
    uint64_t node_id() const { return node_id_; }

    /// Save private key to file (binary format).
    bool save_to_file(const std::string& filename) const;

    /// Load private key from file and recompute public key.
    bool load_from_file(const std::string& filename);

private:
    std::vector<uint8_t> private_key_;
    std::vector<uint8_t> public_key_;
    uint64_t node_id_;
};

} // namespace easytier::crypto
