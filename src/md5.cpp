#include "ntptool/md5.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

namespace ntptool {
namespace {

inline uint32_t rotl32(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

// Per-round left-rotate amounts.
const uint32_t kS[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// K[i] = floor(2^32 * abs(sin(i + 1))).
const uint32_t kK[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

void md5_block(const uint8_t* p, uint32_t& a0, uint32_t& b0, uint32_t& c0,
               uint32_t& d0) {
    uint32_t M[16];
    for (int i = 0; i < 16; ++i) {
        M[i] = static_cast<uint32_t>(p[i * 4]) |
               (static_cast<uint32_t>(p[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(p[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(p[i * 4 + 3]) << 24);
    }
    uint32_t A = a0, B = b0, C = c0, D = d0;
    for (int i = 0; i < 64; ++i) {
        uint32_t F;
        int g;
        if (i < 16) {
            F = (B & C) | (~B & D);
            g = i;
        } else if (i < 32) {
            F = (D & B) | (~D & C);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            F = B ^ C ^ D;
            g = (3 * i + 5) % 16;
        } else {
            F = C ^ (B | ~D);
            g = (7 * i) % 16;
        }
        F = F + A + kK[i] + M[g];
        A = D;
        D = C;
        C = B;
        B = B + rotl32(F, kS[i]);
    }
    a0 += A;
    b0 += B;
    c0 += C;
    d0 += D;
}

}  // namespace

std::array<uint8_t, 16> md5(const uint8_t* data, size_t len) {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    size_t padded = len + 1;
    while (padded % 64 != 56) ++padded;

    std::vector<uint8_t> msg(padded + 8, 0);
    if (len) std::memcpy(msg.data(), data, len);
    msg[len] = 0x80;
    for (int i = 0; i < 8; ++i)
        msg[padded + static_cast<size_t>(i)] =
            static_cast<uint8_t>((bitlen >> (8 * i)) & 0xFF);

    for (size_t off = 0; off < msg.size(); off += 64)
        md5_block(msg.data() + off, a0, b0, c0, d0);

    std::array<uint8_t, 16> out{};
    auto emit = [&](int idx, uint32_t v) {
        out[static_cast<size_t>(idx)] = static_cast<uint8_t>(v & 0xFF);
        out[static_cast<size_t>(idx + 1)] = static_cast<uint8_t>((v >> 8) & 0xFF);
        out[static_cast<size_t>(idx + 2)] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[static_cast<size_t>(idx + 3)] = static_cast<uint8_t>((v >> 24) & 0xFF);
    };
    emit(0, a0);
    emit(4, b0);
    emit(8, c0);
    emit(12, d0);
    return out;
}

std::string md5_hex(const uint8_t* data, size_t len) {
    auto d = md5(data, len);
    std::string s;
    char buf[3];
    for (uint8_t b : d) {
        std::snprintf(buf, sizeof(buf), "%02x", b);
        s += buf;
    }
    return s;
}

}  // namespace ntptool
