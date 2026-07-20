#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace ntptool {

// One-shot SHA-1 (RFC 3174). Used for NTP symmetric-key authentication when the
// configured key uses the SHA1 digest.
std::array<uint8_t, 20> sha1(const uint8_t* data, size_t len);
std::string sha1_hex(const uint8_t* data, size_t len);

}  // namespace ntptool
