#include "easytier/common/protocol.hpp"
#include <random>
#include <cstring>

namespace easytier {

// ============================================================
// Noise payload serialization (binary fallback when no protobuf)
// ============================================================

namespace noise_payload {

// Simple binary format for noise payloads (used when protobuf is not available
// or as a wire-compatible fallback). When protobuf IS available, these are
// serialized as protobuf messages instead.

static void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

static uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static void write_string(uint8_t*& p, const std::string& s) {
    uint16_t len = static_cast<uint16_t>(s.size());
    p[0] = static_cast<uint8_t>(len);
    p[1] = static_cast<uint8_t>(len >> 8);
    p += 2;
    if (len > 0) {
        std::memcpy(p, s.data(), len);
        p += len;
    }
}

static std::string read_string(const uint8_t*& p, size_t& remaining) {
    if (remaining < 2) return {};
    uint16_t len = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
    p += 2; remaining -= 2;
    if (remaining < len) return {};
    std::string s(reinterpret_cast<const char*>(p), len);
    p += len; remaining -= len;
    return s;
}

std::vector<uint8_t> msg1::serialize() const {
    // version(4) + network_name(2+N) + session_gen(4) + conn_id(16) + algo(2+N)
    size_t total = 4 + 2 + network_name.size() + 4 + 16 + 2 + encryption_algorithm.size();
    std::vector<uint8_t> buf(total);
    uint8_t* p = buf.data();
    write_u32_le(p, version); p += 4;
    write_string(p, network_name);
    write_u32_le(p, session_generation); p += 4;
    std::memcpy(p, conn_id, 16); p += 16;
    write_string(p, encryption_algorithm);
    return buf;
}

std::optional<msg1> msg1::deserialize(const uint8_t* data, size_t len) {
    if (len < 4) return std::nullopt;
    msg1 m;
    m.version = read_u32_le(data); data += 4; len -= 4;
    m.network_name = read_string(data, len);
    if (len < 4) return std::nullopt;
    m.session_generation = read_u32_le(data); data += 4; len -= 4;
    if (len < 16) return std::nullopt;
    std::memcpy(m.conn_id, data, 16); data += 16; len -= 16;
    m.encryption_algorithm = read_string(data, len);
    return m;
}

std::vector<uint8_t> msg2::serialize() const {
    size_t total = 2 + network_name.size() + 4 + 1 + 4 + 16 + 16 + 2 + encryption_algorithm.size();
    std::vector<uint8_t> buf(total);
    uint8_t* p = buf.data();
    write_string(p, network_name);
    write_u32_le(p, role_hint); p += 4;
    p[0] = action; p += 1;
    write_u32_le(p, session_generation); p += 4;
    std::memcpy(p, b_conn_id, 16); p += 16;
    std::memcpy(p, a_conn_id_echo, 16); p += 16;
    write_string(p, encryption_algorithm);
    return buf;
}

std::optional<msg2> msg2::deserialize(const uint8_t* data, size_t len) {
    msg2 m;
    m.network_name = read_string(data, len);
    if (len < 4 + 1 + 4 + 16 + 16) return std::nullopt;
    m.role_hint = read_u32_le(data); data += 4; len -= 4;
    m.action = data[0]; data += 1; len -= 1;
    m.session_generation = read_u32_le(data); data += 4; len -= 4;
    std::memcpy(m.b_conn_id, data, 16); data += 16; len -= 16;
    std::memcpy(m.a_conn_id_echo, data, 16); data += 16; len -= 16;
    m.encryption_algorithm = read_string(data, len);
    return m;
}

std::vector<uint8_t> msg3::serialize() const {
    std::vector<uint8_t> buf(16 + 16 + 32);
    std::memcpy(buf.data(), a_conn_id_echo, 16);
    std::memcpy(buf.data() + 16, b_conn_id_echo, 16);
    std::memcpy(buf.data() + 32, secret_digest.data(), 32);
    return buf;
}

std::optional<msg3> msg3::deserialize(const uint8_t* data, size_t len) {
    if (len < 64) return std::nullopt;
    msg3 m;
    std::memcpy(m.a_conn_id_echo, data, 16); data += 16;
    std::memcpy(m.b_conn_id_echo, data, 16); data += 16;
    std::memcpy(m.secret_digest.data(), data, 32);
    return m;
}

} // namespace noise_payload

} // namespace easytier
