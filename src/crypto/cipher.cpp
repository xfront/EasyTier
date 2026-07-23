#include "easytier/crypto/cipher.hpp"
#include "sha256.hpp"
#include <async_net/crypto/aes_gcm.hpp>
#include <cstring>
#include <algorithm>
#include <random>

namespace easytier::crypto {

namespace {

// HKDF-Extract using shared HMAC-SHA256
std::array<uint8_t, 32> hkdf_extract(const uint8_t* salt, size_t salt_len,
                                       const uint8_t* ikm, size_t ikm_len) {
    uint8_t zero_salt[32] = {0};
    if (salt == nullptr || salt_len == 0) {
        salt = zero_salt;
        salt_len = 32;
    }
    return detail::hmac_sha256(salt, salt_len, ikm, ikm_len);
}

// HKDF-Expand using shared HMAC-SHA256
std::vector<uint8_t> hkdf_expand(const uint8_t* prk, size_t prk_len,
                                  const char* info, size_t info_len,
                                  size_t out_len) {
    std::vector<uint8_t> okm;
    uint8_t counter = 1;
    std::array<uint8_t, 32> t{};

    while (okm.size() < out_len) {
        std::vector<uint8_t> input;
        input.insert(input.end(), t.begin(), t.end());
        input.insert(input.end(), reinterpret_cast<const uint8_t*>(info),
                     reinterpret_cast<const uint8_t*>(info) + info_len);
        input.push_back(counter++);

        t = detail::hmac_sha256(prk, prk_len, input.data(), input.size());
        size_t to_copy = std::min(t.size(), out_len - okm.size());
        okm.insert(okm.end(), t.begin(), t.begin() + to_copy);
    }

    return okm;
}

/// Generate random bytes using async_net
std::vector<uint8_t> gen_random(size_t len) {
    return async_net::crypto::aes_gcm::random_bytes(len);
}

} // anonymous namespace

// ============================================================
// Constructors
// ============================================================

session_cipher::session_cipher(const uint8_t key[KEY_LEN_128])
    : key_len_(KEY_LEN_128), is_256_(false) {
    std::memcpy(key_.data(), key, KEY_LEN_128);
}

session_cipher::session_cipher(const uint8_t key[KEY_LEN_256], bool use_256)
    : key_len_(KEY_LEN_256), is_256_(use_256) {
    std::memcpy(key_.data(), key, KEY_LEN_256);
}

session_cipher::session_cipher(const std::vector<uint8_t>& key)
    : is_256_(key.size() > KEY_LEN_128) {
    key_len_ = key.size() > KEY_LEN_128 ? KEY_LEN_256 : KEY_LEN_128;
    std::memcpy(key_.data(), key.data(), std::min(key.size(), key_.size()));
}

// ============================================================
// ZCPacket encrypt/decrypt — Rust-compatible format
// ============================================================

bool session_cipher::encrypt(zc_packet& pkt) {
    auto* pm = pkt.mutable_pm_header();
    if (!pm) return false;
    if (pm->is_encrypted()) return true; // already encrypted

    auto payload = pkt.mutable_payload();
    if (payload.empty()) return true;

    // Generate random 12-byte nonce
    auto nonce_bytes = gen_random(NONCE_LEN);
    uint8_t nonce[NONCE_LEN];
    std::memcpy(nonce, nonce_bytes.data(), NONCE_LEN);

    // Encrypt payload in-place using AES-GCM with empty AAD
    auto ciphertext = async_net::crypto::aes_gcm::encrypt(
        key_.data(), key_len_,
        nonce, NONCE_LEN,
        payload.data(), payload.size(),
        nullptr, 0);

    if (ciphertext.empty()) return false;

    // ciphertext includes the tag appended by AES-GCM
    // Resize payload to hold ciphertext + nonce
    auto& buf = pkt.mutable_buffer();
    size_t pm_off = 0;
    // Calculate PM header offset based on packet type
    switch (pkt.type()) {
        case zc_packet_type::TCP: pm_off = TCP_TUNNEL_HEADER_SIZE; break;
        case zc_packet_type::UDP: pm_off = UDP_TUNNEL_HEADER_SIZE; break;
        case zc_packet_type::WG:  pm_off = WG_TUNNEL_HEADER_SIZE; break;
        case zc_packet_type::DummyTunnel: pm_off = 0; break;
        case zc_packet_type::NIC:
            pm_off = std::max({TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE, WG_TUNNEL_HEADER_SIZE});
            break;
    }
    size_t payload_start = pm_off + PEER_MANAGER_HEADER_SIZE;

    // Replace payload with ciphertext + tail
    buf.resize(payload_start + ciphertext.size() + NONCE_LEN);
    std::memcpy(buf.data() + payload_start, ciphertext.data(), ciphertext.size());
    // Append nonce after ciphertext+tag
    std::memcpy(buf.data() + payload_start + ciphertext.size(), nonce, NONCE_LEN);

    // Update PM header
    pm = pkt.mutable_pm_header();
    pm->set_encrypted(true);
    pm->set_len(static_cast<uint32_t>(ciphertext.size() + NONCE_LEN));

    return true;
}

bool session_cipher::decrypt(zc_packet& pkt) {
    auto* pm = pkt.mutable_pm_header();
    if (!pm) return false;
    if (!pm->is_encrypted()) return true; // not encrypted

    auto payload = pkt.mutable_payload();
    if (payload.size() < TAIL_SIZE) return false;

    // Read tail: [tag:16][nonce:12]
    size_t text_len = payload.size() - TAIL_SIZE;
    const uint8_t* tag_and_nonce = payload.data() + text_len;
    // tag is first 16 bytes, nonce is next 12 bytes (matching Rust StandardAeadTail)
    const uint8_t* tag = tag_and_nonce;
    const uint8_t* nonce = tag_and_nonce + TAG_LEN;

    // Decrypt using AES-GCM with empty AAD
    auto plaintext = async_net::crypto::aes_gcm::decrypt(
        key_.data(), key_len_,
        nonce, NONCE_LEN,
        payload.data(), text_len + TAG_LEN, // ciphertext + tag
        nullptr, 0);

    if (!plaintext) return false;

    // Shrink buffer: remove tail, replace payload with plaintext
    auto& buf = pkt.mutable_buffer();
    size_t pm_off = 0;
    switch (pkt.type()) {
        case zc_packet_type::TCP: pm_off = TCP_TUNNEL_HEADER_SIZE; break;
        case zc_packet_type::UDP: pm_off = UDP_TUNNEL_HEADER_SIZE; break;
        case zc_packet_type::WG:  pm_off = WG_TUNNEL_HEADER_SIZE; break;
        case zc_packet_type::DummyTunnel: pm_off = 0; break;
        case zc_packet_type::NIC:
            pm_off = std::max({TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE, WG_TUNNEL_HEADER_SIZE});
            break;
    }
    size_t payload_start = pm_off + PEER_MANAGER_HEADER_SIZE;
    buf.resize(payload_start + plaintext->size());
    std::memcpy(buf.data() + payload_start, plaintext->data(), plaintext->size());

    // Update PM header
    pm = pkt.mutable_pm_header();
    pm->set_encrypted(false);
    pm->set_len(static_cast<uint32_t>(plaintext->size()));

    return true;
}

// ============================================================
// Raw encrypt/decrypt
// ============================================================

std::vector<uint8_t> session_cipher::encrypt_raw(const uint8_t* plaintext, size_t len) {
    auto nonce_bytes = gen_random(NONCE_LEN);
    uint8_t nonce[NONCE_LEN];
    std::memcpy(nonce, nonce_bytes.data(), NONCE_LEN);

    auto ciphertext = async_net::crypto::aes_gcm::encrypt(
        key_.data(), key_len_,
        nonce, NONCE_LEN,
        plaintext, len,
        nullptr, 0);

    if (ciphertext.empty()) return {};

    // Result: [ciphertext+tag][nonce]
    std::vector<uint8_t> result(ciphertext.size() + NONCE_LEN);
    std::memcpy(result.data(), ciphertext.data(), ciphertext.size());
    std::memcpy(result.data() + ciphertext.size(), nonce, NONCE_LEN);
    return result;
}

std::optional<std::vector<uint8_t>> session_cipher::decrypt_raw(const uint8_t* data, size_t len) {
    if (len < TAIL_SIZE) return std::nullopt;

    size_t text_len = len - TAIL_SIZE;
    const uint8_t* tag_and_nonce = data + text_len;
    const uint8_t* nonce = tag_and_nonce + TAG_LEN;

    auto plaintext = async_net::crypto::aes_gcm::decrypt(
        key_.data(), key_len_,
        nonce, NONCE_LEN,
        data, text_len + TAG_LEN,
        nullptr, 0);

    return plaintext;
}

// ============================================================
// Key derivation
// ============================================================

std::vector<uint8_t> session_cipher::derive_key(const uint8_t* shared_secret, size_t secret_len,
                                                 const uint8_t* salt, size_t salt_len,
                                                 const char* info, size_t info_len) {
    auto prk = hkdf_extract(salt, salt_len, shared_secret, secret_len);
    auto okm = hkdf_expand(prk.data(), prk.size(), info, info_len, KEY_LEN_128);
    return okm;
}

std::vector<uint8_t> session_cipher::generate_key(size_t len) {
    return gen_random(len);
}

std::vector<uint8_t> psk_to_key(const std::string& psk) {
    auto hash = detail::sha256(reinterpret_cast<const uint8_t*>(psk.data()), psk.size());
    // Return first 16 bytes for AES-128-GCM (Rust default)
    return std::vector<uint8_t>(hash.begin(), hash.begin() + 16);
}

} // namespace easytier::crypto
