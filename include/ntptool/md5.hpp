#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace ntptool {

// One-shot MD5 (RFC 1321). Used for NTP symmetric-key authentication.
std::array<uint8_t, 16> md5(const uint8_t* data, size_t len);
std::string md5_hex(const uint8_t* data, size_t len);

}  // namespace ntptool
