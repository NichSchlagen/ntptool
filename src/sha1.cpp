#include "ntptool/sha1.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

namespace ntptool {
namespace {

inline uint32_t rotl32(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}

void sha1_block(const uint8_t* p, uint32_t& h0, uint32_t& h1, uint32_t& h2,
                uint32_t& h3, uint32_t& h4) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(p[i * 4]) << 24) |
               (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(p[i * 4 + 3]));
    }
    for (int i = 16; i < 80; ++i)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = tmp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
}

}  // namespace

std::array<uint8_t, 20> sha1(const uint8_t* data, size_t len) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476,
             h4 = 0xC3D2E1F0;

    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    size_t padded = len + 1;
    while (padded % 64 != 56) ++padded;

    std::vector<uint8_t> msg(padded + 8, 0);
    if (len) std::memcpy(msg.data(), data, len);
    msg[len] = 0x80;
    for (int i = 0; i < 8; ++i)
        msg[padded + static_cast<size_t>(i)] =
            static_cast<uint8_t>((bitlen >> (56 - 8 * i)) & 0xFF);

    for (size_t off = 0; off < msg.size(); off += 64)
        sha1_block(msg.data() + off, h0, h1, h2, h3, h4);

    std::array<uint8_t, 20> out{};
    uint32_t hs[5] = {h0, h1, h2, h3, h4};
    for (int i = 0; i < 5; ++i) {
        out[static_cast<size_t>(i * 4)] = static_cast<uint8_t>((hs[i] >> 24) & 0xFF);
        out[static_cast<size_t>(i * 4 + 1)] = static_cast<uint8_t>((hs[i] >> 16) & 0xFF);
        out[static_cast<size_t>(i * 4 + 2)] = static_cast<uint8_t>((hs[i] >> 8) & 0xFF);
        out[static_cast<size_t>(i * 4 + 3)] = static_cast<uint8_t>(hs[i] & 0xFF);
    }
    return out;
}

std::string sha1_hex(const uint8_t* data, size_t len) {
    auto d = sha1(data, len);
    std::string s;
    char buf[3];
    for (uint8_t b : d) {
        std::snprintf(buf, sizeof(buf), "%02x", b);
        s += buf;
    }
    return s;
}

}  // namespace ntptool
