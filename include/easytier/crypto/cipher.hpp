#pragma once

#include <easytier/common/zc_packet.hpp>
#include <async_net/crypto/aes_gcm.hpp>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>
#include <array>
#include <cstring>
#include <string>

namespace easytier::crypto {

/// Session cipher — AES-GCM encryption compatible with Rust EasyTier.
///
/// Rust wire format for encrypted payload (after PeerManagerHeader):
///   [original_payload][tag:16][nonce:12]
///
/// The PeerManagerHeader.flags bit 0 (ENCRYPTED) is set when encrypted.
/// AES-GCM is used with empty AAD (no additional authenticated data).
///
/// Two key sizes supported:
///   - AES-128-GCM: 16-byte key (default in Rust)
///   - AES-256-GCM: 32-byte key
class session_cipher {
public:
    static constexpr size_t KEY_LEN_128 = 16;
    static constexpr size_t KEY_LEN_256 = 32;
    static constexpr size_t TAG_LEN     = 16;
    static constexpr size_t NONCE_LEN   = 12;
    static constexpr size_t TAIL_SIZE   = TAG_LEN + NONCE_LEN; // 28

    /// Construct with a 16-byte key (AES-128-GCM, Rust default)
    explicit session_cipher(const uint8_t key[KEY_LEN_128]);

    /// Construct with a 32-byte key (AES-256-GCM)
    session_cipher(const uint8_t key[KEY_LEN_256], bool use_256);

    /// Construct from vector key (auto-detect size)
    explicit session_cipher(const std::vector<uint8_t>& key);

    /// Encrypt a ZCPacket in-place.
    /// Appends [tag:16][nonce:12] to payload and sets ENCRYPTED flag.
    /// Returns true on success.
    bool encrypt(zc_packet& pkt);

    /// Decrypt a ZCPacket in-place.
    /// Reads [tag:16][nonce:12] from payload tail, decrypts, clears ENCRYPTED flag.
    /// Returns true on success, false on auth failure.
    bool decrypt(zc_packet& pkt);

    /// Encrypt raw payload bytes. Returns [ciphertext][tag:16][nonce:12].
    std::vector<uint8_t> encrypt_raw(const uint8_t* plaintext, size_t len);

    /// Decrypt raw payload bytes. Input: [ciphertext][tag:16][nonce:12].
    /// Returns plaintext on success, nullopt on failure.
    std::optional<std::vector<uint8_t>> decrypt_raw(const uint8_t* data, size_t len);

    /// Get the encryption algorithm name (for handshake)
    std::string algorithm_name() const { return is_256_ ? "aes-gcm-256" : "aes-gcm"; }

    /// Derive a session key from shared secret using HKDF-SHA256
    static std::vector<uint8_t> derive_key(const uint8_t* shared_secret, size_t secret_len,
                                            const uint8_t* salt, size_t salt_len,
                                            const char* info, size_t info_len);

    /// Generate a random key (16 or 32 bytes)
    static std::vector<uint8_t> generate_key(size_t len = KEY_LEN_128);

private:
    std::array<uint8_t, KEY_LEN_256> key_{};
    size_t key_len_;
    bool is_256_;
};

/// Derive a key from a pre-shared key string using SHA-256
std::vector<uint8_t> psk_to_key(const std::string& psk);

} // namespace easytier::crypto
