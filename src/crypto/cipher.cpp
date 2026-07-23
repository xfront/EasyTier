#include "easytier/crypto/cipher.hpp"
#include "sha256.hpp"
#include <async_net/crypto/aes_gcm.hpp>
#include <cstring>
#include <algorithm>

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

} // anonymous namespace

session_cipher::session_cipher(const uint8_t key[KEY_LEN]) {
    std::memcpy(key_.data(), key, KEY_LEN);
}

session_cipher::session_cipher(const std::vector<uint8_t>& key) {
    if (key.size() >= KEY_LEN) {
        std::memcpy(key_.data(), key.data(), KEY_LEN);
    }
}

void session_cipher::build_aad(uint8_t* aad, uint64_t src_node, uint64_t dst_node, uint32_t seq) const {
    for (int i = 0; i < 8; ++i) {
        aad[i] = (src_node >> (56 - i * 8)) & 0xff;
        aad[8 + i] = (dst_node >> (56 - i * 8)) & 0xff;
    }
    aad[16] = (seq >> 24) & 0xff;
    aad[17] = (seq >> 16) & 0xff;
    aad[18] = (seq >> 8) & 0xff;
    aad[19] = seq & 0xff;
}

void session_cipher::build_nonce(uint8_t* nonce, uint32_t seq) const {
    std::memcpy(nonce, key_.data(), 4);
    std::memset(nonce + 4, 0, 4);
    nonce[8] = (seq >> 24) & 0xff;
    nonce[9] = (seq >> 16) & 0xff;
    nonce[10] = (seq >> 8) & 0xff;
    nonce[11] = seq & 0xff;
}

std::vector<uint8_t> session_cipher::encrypt(const uint8_t* plaintext, size_t len,
                                              uint32_t seq,
                                              uint64_t src_node, uint64_t dst_node) {
    uint8_t aad[20];
    build_aad(aad, src_node, dst_node, seq);

    uint8_t nonce[12];
    build_nonce(nonce, seq);

    auto ciphertext = async_net::crypto::aes_gcm::encrypt(
        key_.data(), KEY_LEN,
        nonce, sizeof(nonce),
        plaintext, len,
        aad, sizeof(aad));

    if (ciphertext.empty()) return {};

    std::vector<uint8_t> result(4 + 8 + ciphertext.size());
    result[0] = (seq >> 24) & 0xff;
    result[1] = (seq >> 16) & 0xff;
    result[2] = (seq >> 8) & 0xff;
    result[3] = seq & 0xff;
    std::memcpy(result.data() + 4, nonce, 8);
    std::memcpy(result.data() + 12, ciphertext.data(), ciphertext.size());

    return result;
}

std::optional<std::vector<uint8_t>> session_cipher::decrypt(const uint8_t* data, size_t len,
                                                              uint64_t src_node, uint64_t dst_node) {
    if (len < OVERHEAD) return std::nullopt;

    uint32_t seq = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];

    if (seq < recv_seq_) return std::nullopt;

    uint8_t nonce[12];
    std::memcpy(nonce, key_.data(), 4);
    std::memset(nonce + 4, 0, 4);
    nonce[8] = (seq >> 24) & 0xff;
    nonce[9] = (seq >> 16) & 0xff;
    nonce[10] = (seq >> 8) & 0xff;
    nonce[11] = seq & 0xff;

    const uint8_t* ciphertext = data + 12;
    size_t ciphertext_len = len - 12;

    uint8_t aad[20];
    build_aad(aad, src_node, dst_node, seq);

    auto plaintext = async_net::crypto::aes_gcm::decrypt(
        key_.data(), KEY_LEN,
        nonce, sizeof(nonce),
        ciphertext, ciphertext_len,
        aad, sizeof(aad));

    if (!plaintext) return std::nullopt;

    recv_seq_ = seq + 1;
    return plaintext;
}

std::vector<uint8_t> session_cipher::derive_key(const uint8_t* shared_secret, size_t secret_len,
                                                 const uint8_t* salt, size_t salt_len,
                                                 const char* info, size_t info_len) {
    auto prk = hkdf_extract(salt, salt_len, shared_secret, secret_len);
    auto okm = hkdf_expand(prk.data(), prk.size(), info, info_len, KEY_LEN);
    return okm;
}

std::vector<uint8_t> session_cipher::generate_key() {
    return async_net::crypto::aes_gcm::random_bytes(KEY_LEN);
}

std::vector<uint8_t> psk_to_key(const std::string& psk) {
    auto hash = detail::sha256(reinterpret_cast<const uint8_t*>(psk.data()), psk.size());
    return std::vector<uint8_t>(hash.begin(), hash.end());
}

} // namespace easytier::crypto
