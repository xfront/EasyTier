#pragma once

#include <async_net/crypto/aes_gcm.hpp>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>
#include <array>
#include <cstring>

namespace easytier::crypto {

/// Session cipher — AES-256-GCM encryption for peer-to-peer data frames.
///
/// Wire format for encrypted payload:
///   [seq:4][nonce:8][ciphertext:N][tag:16]
///
/// The AAD (additional authenticated data) contains:
///   [src_node_id:8][dst_node_id:8][seq:4]
/// to prevent replay and misdirection attacks.
///
/// Usage:
///   session_cipher cipher(shared_key);
///   auto encrypted = cipher.encrypt(plaintext, len, seq, src, dst);
///   auto decrypted = cipher.decrypt(encrypted_data, len, src, dst);
class session_cipher {
public:
    static constexpr size_t KEY_LEN = 32;
    static constexpr size_t NONCE_LEN = 8;
    static constexpr size_t SEQ_LEN = 4;
    static constexpr size_t TAG_LEN = 16;
    static constexpr size_t OVERHEAD = SEQ_LEN + NONCE_LEN + TAG_LEN;  // 28 bytes

    /// Construct with a 32-byte shared key.
    explicit session_cipher(const uint8_t key[KEY_LEN]);

    /// Construct from a vector key.
    explicit session_cipher(const std::vector<uint8_t>& key);

    /// Encrypt plaintext with sequence number and node IDs for AAD.
    /// Returns: [seq:4][nonce:8][ciphertext:N][tag:16]
    std::vector<uint8_t> encrypt(const uint8_t* plaintext, size_t len,
                                  uint32_t seq,
                                  uint64_t src_node, uint64_t dst_node);

    /// Decrypt ciphertext. Returns plaintext on success, nullopt on auth failure.
    /// Input: [seq:4][nonce:8][ciphertext:N][tag:16]
    std::optional<std::vector<uint8_t>> decrypt(const uint8_t* data, size_t len,
                                                  uint64_t src_node, uint64_t dst_node);

    /// Get the next sequence number (auto-incrementing).
    uint32_t next_seq() { return send_seq_++; }

    /// Get the current send sequence number.
    uint32_t current_seq() const { return send_seq_; }

    /// Derive a session key from a shared secret using HKDF-SHA256.
    /// Uses the async_net AES-GCM random_bytes for salt generation.
    static std::vector<uint8_t> derive_key(const uint8_t* shared_secret, size_t secret_len,
                                            const uint8_t* salt, size_t salt_len,
                                            const char* info, size_t info_len);

    /// Generate a random 32-byte key.
    static std::vector<uint8_t> generate_key();

private:
    /// Build AAD bytes: [src_node:8][dst_node:8][seq:4]
    void build_aad(uint8_t* aad, uint64_t src_node, uint64_t dst_node, uint32_t seq) const;

    /// Build 12-byte nonce for AES-GCM: [fixed:4][counter:8]
    void build_nonce(uint8_t* nonce, uint32_t seq) const;

    std::array<uint8_t, KEY_LEN> key_;
    uint32_t send_seq_ = 0;
    uint32_t recv_seq_ = 0;  // For replay protection
};

/// Derive a shared key from a pre-shared key (PSK) string.
/// Uses SHA-256 hash of the PSK as the key material.
std::vector<uint8_t> psk_to_key(const std::string& psk);

} // namespace easytier::crypto
