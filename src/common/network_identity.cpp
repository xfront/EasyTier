#include "easytier/common/network_identity.hpp"
#include <cstring>
#include <algorithm>

namespace easytier {

// ============================================================
// SipHash-2-4 — compatible with Rust std::collections::hash_map::DefaultHasher
//
// Rust's DefaultHasher uses:
//   k0 = 0x0706050403020100
//   k1 = 0x0f0e0d0c0b0a0908
//   v0 = k0 ^ 0x736f6d6570736575
//   v1 = k1 ^ 0x646f72616e646f6d
//   v2 = k0 ^ 0x6c7967656e657261
//   v3 = k1 ^ 0x7465646279746573
// ============================================================

static constexpr uint64_t SIP_K0 = 0x0706050403020100ULL;
static constexpr uint64_t SIP_K1 = 0x0f0e0d0c0b0a0908ULL;

static inline uint64_t rotl64(uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

sip_hasher::sip_hasher()
    : k0(SIP_K0), k1(SIP_K1), total_len(0), buf_len(0)
{
    v0 = k0 ^ 0x736f6d6570736575ULL;
    v1 = k1 ^ 0x646f72616e646f6dULL;
    v2 = k0 ^ 0x6c7967656e657261ULL;
    v3 = k1 ^ 0x7465646279746573ULL;
    std::memset(buf, 0, sizeof(buf));
}

void sip_hasher::sip_round() {
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
}

void sip_hasher::process_block(uint64_t m) {
    v3 ^= m;
    sip_round();
    sip_round();
    v0 ^= m;
}

static uint64_t read_le64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0])
         | (static_cast<uint64_t>(p[1]) << 8)
         | (static_cast<uint64_t>(p[2]) << 16)
         | (static_cast<uint64_t>(p[3]) << 24)
         | (static_cast<uint64_t>(p[4]) << 32)
         | (static_cast<uint64_t>(p[5]) << 40)
         | (static_cast<uint64_t>(p[6]) << 48)
         | (static_cast<uint64_t>(p[7]) << 56);
}

void sip_hasher::write(const uint8_t* data, size_t len) {
    total_len += len;
    const uint8_t* p = data;

    // Fill internal buffer first
    if (buf_len > 0) {
        size_t need = 8 - buf_len;
        size_t copy = std::min(len, need);
        std::memcpy(buf + buf_len, p, copy);
        buf_len += copy;
        p += copy;
        len -= copy;
        if (buf_len == 8) {
            process_block(read_le64(buf));
            buf_len = 0;
        }
    }

    // Process full 8-byte blocks
    while (len >= 8) {
        process_block(read_le64(p));
        p += 8;
        len -= 8;
    }

    // Buffer remaining bytes
    if (len > 0) {
        std::memcpy(buf, p, len);
        buf_len = len;
    }
}

uint64_t sip_hasher::finish() {
    // Final block: remaining bytes + length in last byte
    uint64_t b = (total_len & 0xFF) << 56;
    if (buf_len >= 7) b |= static_cast<uint64_t>(buf[6]) << 48;
    if (buf_len >= 6) b |= static_cast<uint64_t>(buf[5]) << 40;
    if (buf_len >= 5) b |= static_cast<uint64_t>(buf[4]) << 32;
    if (buf_len >= 4) b |= static_cast<uint64_t>(buf[3]) << 24;
    if (buf_len >= 3) b |= static_cast<uint64_t>(buf[2]) << 16;
    if (buf_len >= 2) b |= static_cast<uint64_t>(buf[1]) << 8;
    if (buf_len >= 1) b |= static_cast<uint64_t>(buf[0]);

    process_block(b);

    // Finalization
    v2 ^= 0xFF;
    sip_round();
    sip_round();
    sip_round();
    sip_round();

    return v0 ^ v1 ^ v2 ^ v3;
}

// ============================================================
// generate_digest_from_str — compatible with Rust EasyTier
// ============================================================

network_digest_t generate_digest_from_str(const std::string& str1, const std::string& str2) {
    network_digest_t digest{};

    sip_hasher hasher;
    hasher.write(str1);
    hasher.write(str2);

    // digest is 32 bytes = 4 shards of 8 bytes each
    for (int i = 0; i < 4; ++i) {
        uint64_t h = hasher.finish();
        // to_be_bytes: big-endian
        digest[i * 8 + 0] = static_cast<uint8_t>((h >> 56) & 0xFF);
        digest[i * 8 + 1] = static_cast<uint8_t>((h >> 48) & 0xFF);
        digest[i * 8 + 2] = static_cast<uint8_t>((h >> 40) & 0xFF);
        digest[i * 8 + 3] = static_cast<uint8_t>((h >> 32) & 0xFF);
        digest[i * 8 + 4] = static_cast<uint8_t>((h >> 24) & 0xFF);
        digest[i * 8 + 5] = static_cast<uint8_t>((h >> 16) & 0xFF);
        digest[i * 8 + 6] = static_cast<uint8_t>((h >>  8) & 0xFF);
        digest[i * 8 + 7] = static_cast<uint8_t>( h        & 0xFF);

        // Feed back into hasher: write digest[0..(i+1)*8]
        hasher.write(digest.data(), (i + 1) * 8);
    }

    return digest;
}

} // namespace easytier
