#include "easytier/crypto/key_exchange.hpp"
#include "easytier/crypto/cipher.hpp"
#include "sha256.hpp"
#include <async_net/crypto/aes_gcm.hpp>
#include <fstream>
#include <cstring>

namespace easytier::crypto {

// Minimal X25519 implementation based on Curve25519
// This is a simplified implementation for educational purposes
// For production use, consider libsodium or OpenSSL

namespace {

// Field element: 10 limbs of 26 bits each (radix 2^25.5)
struct fe {
    int32_t v[10];

    fe() { std::memset(v, 0, sizeof(v)); }
    fe(int32_t v0, int32_t v1, int32_t v2, int32_t v3, int32_t v4,
       int32_t v5, int32_t v6, int32_t v7, int32_t v8, int32_t v9)
        : v{v0, v1, v2, v3, v4, v5, v6, v7, v8, v9} {}
};

inline int64_t load_3(const uint8_t* in) {
    return (int64_t)in[0] | ((int64_t)in[1] << 8) | ((int64_t)in[2] << 16);
}

inline int64_t load_4(const uint8_t* in) {
    return (int64_t)in[0] | ((int64_t)in[1] << 8) | ((int64_t)in[2] << 16) | ((int64_t)in[3] << 24);
}

void fe_frombytes(fe& h, const uint8_t* s) {
    int64_t h0 = load_4(s);
    int64_t h1 = load_3(s + 4) << 6;
    int64_t h2 = load_3(s + 7) << 5;
    int64_t h3 = load_3(s + 10) << 3;
    int64_t h4 = load_3(s + 13) << 2;
    int64_t h5 = load_4(s + 16);
    int64_t h6 = load_3(s + 20) << 7;
    int64_t h7 = load_3(s + 23) << 5;
    int64_t h8 = load_3(s + 26) << 4;
    int64_t h9 = (load_3(s + 29) & 0x7fffff) << 2;

    int64_t carry9 = (h9 + (1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    int64_t carry1 = (h1 + (1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    int64_t carry3 = (h3 + (1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    int64_t carry5 = (h5 + (1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    int64_t carry7 = (h7 + (1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

    int64_t carry0 = (h0 + (1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    int64_t carry2 = (h2 + (1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    int64_t carry4 = (h4 + (1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    int64_t carry6 = (h6 + (1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    int64_t carry8 = (h8 + (1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

    h.v[0] = (int32_t)h0; h.v[1] = (int32_t)h1; h.v[2] = (int32_t)h2;
    h.v[3] = (int32_t)h3; h.v[4] = (int32_t)h4; h.v[5] = (int32_t)h5;
    h.v[6] = (int32_t)h6; h.v[7] = (int32_t)h7; h.v[8] = (int32_t)h8;
    h.v[9] = (int32_t)h9;
}

void fe_tobytes(uint8_t* s, const fe& h) {
    int32_t t[10];
    for (int i = 0; i < 10; i++) t[i] = h.v[i];

    int32_t q = (19 * t[9] + (1 << 24)) >> 25;
    for (int i = 0; i < 5; i++) {
        q = (t[2*i] + q) >> 26;
        q = (t[2*i+1] + q) >> 25;
    }
    t[0] += 19 * q;

    int32_t carry = 0;
    for (int i = 0; i < 10; i++) {
        t[i] += carry;
        if (i & 1) {
            carry = t[i] >> 25;
            t[i] -= carry << 25;
        } else {
            carry = t[i] >> 26;
            t[i] -= carry << 26;
        }
    }

    s[0] = t[0] & 0xff; s[1] = (t[0] >> 8) & 0xff; s[2] = (t[0] >> 16) & 0xff;
    s[3] = ((t[0] >> 24) | (t[1] << 2)) & 0xff;
    s[4] = (t[1] >> 6) & 0xff; s[5] = (t[1] >> 14) & 0xff;
    s[6] = ((t[1] >> 22) | (t[2] << 3)) & 0xff;
    s[7] = (t[2] >> 5) & 0xff; s[8] = (t[2] >> 13) & 0xff;
    s[9] = ((t[2] >> 21) | (t[3] << 5)) & 0xff;
    s[10] = (t[3] >> 3) & 0xff; s[11] = (t[3] >> 11) & 0xff;
    s[12] = ((t[3] >> 19) | (t[4] << 6)) & 0xff;
    s[13] = (t[4] >> 2) & 0xff; s[14] = (t[4] >> 10) & 0xff;
    s[15] = (t[4] >> 18) & 0xff;
    s[16] = t[5] & 0xff; s[17] = (t[5] >> 8) & 0xff; s[18] = (t[5] >> 16) & 0xff;
    s[19] = ((t[5] >> 24) | (t[6] << 1)) & 0xff;
    s[20] = (t[6] >> 7) & 0xff; s[21] = (t[6] >> 15) & 0xff;
    s[22] = ((t[6] >> 23) | (t[7] << 3)) & 0xff;
    s[23] = (t[7] >> 5) & 0xff; s[24] = (t[7] >> 13) & 0xff;
    s[25] = ((t[7] >> 21) | (t[8] << 4)) & 0xff;
    s[26] = (t[8] >> 4) & 0xff; s[27] = (t[8] >> 12) & 0xff;
    s[28] = ((t[8] >> 20) | (t[9] << 6)) & 0xff;
    s[29] = (t[9] >> 2) & 0xff; s[30] = (t[9] >> 10) & 0xff;
    s[31] = (t[9] >> 18) & 0xff;
}

void fe_add(fe& h, const fe& f, const fe& g) {
    for (int i = 0; i < 10; i++) h.v[i] = f.v[i] + g.v[i];
}

void fe_sub(fe& h, const fe& f, const fe& g) {
    for (int i = 0; i < 10; i++) h.v[i] = f.v[i] - g.v[i];
}

void fe_mul(fe& h, const fe& f, const fe& g) {
    int64_t f0=f.v[0],f1=f.v[1],f2=f.v[2],f3=f.v[3],f4=f.v[4];
    int64_t f5=f.v[5],f6=f.v[6],f7=f.v[7],f8=f.v[8],f9=f.v[9];
    int64_t g0=g.v[0],g1=g.v[1],g2=g.v[2],g3=g.v[3],g4=g.v[4];
    int64_t g5=g.v[5],g6=g.v[6],g7=g.v[7],g8=g.v[8],g9=g.v[9];
    int64_t g1_19=19*g1,g2_19=19*g2,g3_19=19*g3,g4_19=19*g4,g5_19=19*g5;
    int64_t g6_19=19*g6,g7_19=19*g7,g8_19=19*g8,g9_19=19*g9;
    int64_t f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;

    int64_t h0=f0*g0+f1_2*g9_19+f2*g8_19+f3_2*g7_19+f4*g6_19+f5_2*g5_19+f6*g4_19+f7_2*g3_19+f8*g2_19+f9_2*g1_19;
    int64_t h1=f0*g1+f1*g0+f2*g9_19+f3*g8_19+f4*g7_19+f5*g6_19+f6*g5_19+f7*g4_19+f8*g3_19+f9*g2_19;
    int64_t h2=f0*g2+f1_2*g1+f2*g0+f3_2*g9_19+f4*g8_19+f5_2*g7_19+f6*g6_19+f7_2*g5_19+f8*g4_19+f9_2*g3_19;
    int64_t h3=f0*g3+f1*g2+f2*g1+f3*g0+f4*g9_19+f5*g8_19+f6*g7_19+f7*g6_19+f8*g5_19+f9*g4_19;
    int64_t h4=f0*g4+f1_2*g3+f2*g2+f3_2*g1+f4*g0+f5_2*g9_19+f6*g8_19+f7_2*g7_19+f8*g6_19+f9_2*g5_19;
    int64_t h5=f0*g5+f1*g4+f2*g3+f3*g2+f4*g1+f5*g0+f6*g9_19+f7*g8_19+f8*g7_19+f9*g6_19;
    int64_t h6=f0*g6+f1_2*g5+f2*g4+f3_2*g3+f4*g2+f5_2*g1+f6*g0+f7_2*g9_19+f8*g8_19+f9_2*g7_19;
    int64_t h7=f0*g7+f1*g6+f2*g5+f3*g4+f4*g3+f5*g2+f6*g1+f7*g0+f8*g9_19+f9*g8_19;
    int64_t h8=f0*g8+f1_2*g7+f2*g6+f3_2*g5+f4*g4+f5_2*g3+f6*g2+f7_2*g1+f8*g0+f9_2*g9_19;
    int64_t h9=f0*g9+f1*g8+f2*g7+f3*g6+f4*g5+f5*g4+f6*g3+f7*g2+f8*g1+f9*g0;

    int64_t carry0=(h0+(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    int64_t carry4=(h4+(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    int64_t carry1=(h1+(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    int64_t carry5=(h5+(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    int64_t carry2=(h2+(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    int64_t carry6=(h6+(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    int64_t carry3=(h3+(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    int64_t carry7=(h7+(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    int64_t carry8=(h8+(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    int64_t carry9=(h9+(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(1<<25))>>26; h1+=carry0; h0-=carry0<<26;

    h.v[0]=(int32_t)h0; h.v[1]=(int32_t)h1; h.v[2]=(int32_t)h2; h.v[3]=(int32_t)h3;
    h.v[4]=(int32_t)h4; h.v[5]=(int32_t)h5; h.v[6]=(int32_t)h6; h.v[7]=(int32_t)h7;
    h.v[8]=(int32_t)h8; h.v[9]=(int32_t)h9;
}

void fe_sq(fe& h, const fe& f) {
    fe_mul(h, f, f);
}

void fe_invert(fe& out, const fe& z) {
    fe t0, t1, t2, t3;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (i = 0; i < 4; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 0; i < 99; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

void fe_pow2523(fe& out, const fe& z) {
    fe t0, t1, t2;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 0; i < 9; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 0; i < 19; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 0; i < 9; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 0; i < 49; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 0; i < 99; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 0; i < 49; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    for (i = 0; i < 2; i++) fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

void fe_cmov(fe& f, const fe& g, int b) {
    int32_t mask = -b;
    for (int i = 0; i < 10; i++) {
        f.v[i] ^= mask & (f.v[i] ^ g.v[i]);
    }
}

void fe_mul121666(fe& h, const fe& f, int32_t m) {
    int64_t f0=f.v[0],f1=f.v[1],f2=f.v[2],f3=f.v[3],f4=f.v[4];
    int64_t f5=f.v[5],f6=f.v[6],f7=f.v[7],f8=f.v[8],f9=f.v[9];
    int64_t h0=f0*m, h1=f1*m, h2=f2*m, h3=f3*m, h4=f4*m;
    int64_t h5=f5*m, h6=f6*m, h7=f7*m, h8=f8*m, h9=f9*m;

    int64_t carry0=(h0+(1<<25))>>26; h1+=carry0; h0-=carry0<<26;
    int64_t carry4=(h4+(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    int64_t carry1=(h1+(1<<24))>>25; h2+=carry1; h1-=carry1<<25;
    int64_t carry5=(h5+(1<<24))>>25; h6+=carry5; h5-=carry5<<25;
    int64_t carry2=(h2+(1<<25))>>26; h3+=carry2; h2-=carry2<<26;
    int64_t carry6=(h6+(1<<25))>>26; h7+=carry6; h6-=carry6<<26;
    int64_t carry3=(h3+(1<<24))>>25; h4+=carry3; h3-=carry3<<25;
    int64_t carry7=(h7+(1<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(1<<25))>>26; h5+=carry4; h4-=carry4<<26;
    int64_t carry8=(h8+(1<<25))>>26; h9+=carry8; h8-=carry8<<26;
    int64_t carry9=(h9+(1<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(1<<25))>>26; h1+=carry0; h0-=carry0<<26;

    h.v[0]=(int32_t)h0; h.v[1]=(int32_t)h1; h.v[2]=(int32_t)h2; h.v[3]=(int32_t)h3;
    h.v[4]=(int32_t)h4; h.v[5]=(int32_t)h5; h.v[6]=(int32_t)h6; h.v[7]=(int32_t)h7;
    h.v[8]=(int32_t)h8; h.v[9]=(int32_t)h9;
}

// X25519 scalar multiplication
void x25519_scalarmult(uint8_t* q, const uint8_t* n, const uint8_t* p) {
    uint8_t e[32];
    for (int i = 0; i < 32; i++) e[i] = n[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, p);
    x2.v[0] = 1; x2.v[1] = 0; x2.v[2] = 0; x2.v[3] = 0;
    x2.v[4] = 0; x2.v[5] = 0; x2.v[6] = 0; x2.v[7] = 0;
    x2.v[8] = 0; x2.v[9] = 0;
    z2.v[0] = 0; z2.v[1] = 0; z2.v[2] = 0; z2.v[3] = 0;
    z2.v[4] = 0; z2.v[5] = 0; z2.v[6] = 0; z2.v[7] = 0;
    z2.v[8] = 0; z2.v[9] = 0;
    x3.v[0] = x1.v[0]; x3.v[1] = x1.v[1]; x3.v[2] = x1.v[2]; x3.v[3] = x1.v[3];
    x3.v[4] = x1.v[4]; x3.v[5] = x1.v[5]; x3.v[6] = x1.v[6]; x3.v[7] = x1.v[7];
    x3.v[8] = x1.v[8]; x3.v[9] = x1.v[9];
    z3.v[0] = 1; z3.v[1] = 0; z3.v[2] = 0; z3.v[3] = 0;
    z3.v[4] = 0; z3.v[5] = 0; z3.v[6] = 0; z3.v[7] = 0;
    z3.v[8] = 0; z3.v[9] = 0;

    int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        int b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cmov(x2, x3, swap);
        fe_cmov(z2, z3, swap);
        swap = b;

        fe A, B, C, D, DA, CB, E, AA, BB, E_2, t0, t1;
        fe_add(A, x2, z2);
        fe_sq(AA, A);
        fe_sub(B, x2, z2);
        fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);
        fe_add(x3, DA, CB);
        fe_sq(x3, x3);
        fe_sub(z3, DA, CB);
        fe_sq(z3, z3);
        fe_mul(z3, z3, x1);
        fe_mul(x2, AA, BB);
        fe_mul121666(E_2, E, 121666);
        fe_add(t0, AA, E_2);
        fe_mul(z2, E, t0);
    }

    fe_cmov(x2, x3, swap);
    fe_cmov(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);
}

// X25519 base point (u=9)
const uint8_t X25519_BASEPOINT[32] = {9};

} // anonymous namespace

std::vector<uint8_t> key_exchange::generate_private_key() {
    return async_net::crypto::aes_gcm::random_bytes(PRIVATE_KEY_LEN);
}

std::vector<uint8_t> key_exchange::compute_public_key(const uint8_t private_key[PRIVATE_KEY_LEN]) {
    std::vector<uint8_t> public_key(PUBLIC_KEY_LEN);
    x25519_scalarmult(public_key.data(), private_key, X25519_BASEPOINT);
    return public_key;
}

std::vector<uint8_t> key_exchange::compute_shared_secret(
    const uint8_t private_key[PRIVATE_KEY_LEN],
    const uint8_t peer_public[PUBLIC_KEY_LEN]) {
    std::vector<uint8_t> shared(SHARED_SECRET_LEN);
    x25519_scalarmult(shared.data(), private_key, peer_public);
    return shared;
}

uint64_t key_exchange::derive_node_id(const uint8_t public_key[PUBLIC_KEY_LEN]) {
    auto hash = detail::sha256(public_key, PUBLIC_KEY_LEN);
    uint64_t id = 0;
    for (int i = 0; i < 8; i++) {
        id = (id << 8) | hash[i];
    }
    return id;
}

key_exchange::exchange_result key_exchange::perform_exchange(
    const uint8_t my_private[PRIVATE_KEY_LEN],
    const uint8_t peer_public[PUBLIC_KEY_LEN],
    const uint8_t* salt, size_t salt_len,
    const char* info, size_t info_len) {

    exchange_result result;
    result.shared_secret = compute_shared_secret(my_private, peer_public);
    result.peer_node_id = derive_node_id(peer_public);

    // Derive session key using HKDF
    result.session_key = session_cipher::derive_key(
        result.shared_secret.data(), result.shared_secret.size(),
        salt, salt_len,
        info, info_len);

    return result;
}

key_pair::key_pair() {
    private_key_ = key_exchange::generate_private_key();
    public_key_ = key_exchange::compute_public_key(private_key_.data());
    node_id_ = key_exchange::derive_node_id(public_key_.data());
}

key_pair::key_pair(const std::vector<uint8_t>& private_key)
    : private_key_(private_key) {
    public_key_ = key_exchange::compute_public_key(private_key_.data());
    node_id_ = key_exchange::derive_node_id(public_key_.data());
}

bool key_pair::save_to_file(const std::string& filename) const {
    std::ofstream f(filename, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(private_key_.data()), private_key_.size());
    return f.good();
}

bool key_pair::load_from_file(const std::string& filename) {
    std::ifstream f(filename, std::ios::binary | std::ios::ate);
    if (!f) return false;

    auto size = f.tellg();
    if (size != static_cast<std::streamsize>(key_exchange::PRIVATE_KEY_LEN)) return false;

    f.seekg(0);
    private_key_.resize(key_exchange::PRIVATE_KEY_LEN);
    f.read(reinterpret_cast<char*>(private_key_.data()), key_exchange::PRIVATE_KEY_LEN);

    public_key_ = key_exchange::compute_public_key(private_key_.data());
    node_id_ = key_exchange::derive_node_id(public_key_.data());
    return true;
}

} // namespace easytier::crypto
