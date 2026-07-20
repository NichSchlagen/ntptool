#pragma once

// -----------------------------------------------------------------------------
// Small, dependency-free utility helpers: big-endian byte packing, string
// manipulation, time formatting and hex dumps.
// -----------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

namespace ntptool {

// ---- Big-endian (network byte order) integer (de)serialisation --------------

inline uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
inline uint32_t get_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           (static_cast<uint32_t>(p[3]));
}
inline uint64_t get_u64(const uint8_t* p) {
    return (static_cast<uint64_t>(get_u32(p)) << 32) |
           static_cast<uint64_t>(get_u32(p + 4));
}

inline void put_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}
inline void put_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}
inline void put_u64(std::vector<uint8_t>& v, uint64_t x) {
    put_u32(v, static_cast<uint32_t>(x >> 32));
    put_u32(v, static_cast<uint32_t>(x & 0xFFFFFFFFu));
}

// ---- String helpers ---------------------------------------------------------

std::string to_lower(std::string s);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
bool iequals(const std::string& a, const std::string& b);
bool starts_with(const std::string& s, const std::string& prefix);

// JSON-escape a string (without surrounding quotes).
std::string json_escape(const std::string& s);

// CSV-escape a field (adds quoting when required).
std::string csv_escape(const std::string& s);

// ---- Numeric / time formatting ----------------------------------------------

// Format a duration given in seconds using an adaptive unit (ns/us/ms/s).
std::string format_seconds_adaptive(double seconds);

// Format a signed offset in milliseconds with an explicit sign.
std::string format_ms_signed(double seconds);

// Format a UNIX timestamp (seconds since 1970, may carry a fraction) as an
// ISO-8601 UTC string.
std::string format_unix_utc(double unix_seconds, bool with_fraction = true);

// ---- Diagnostics ------------------------------------------------------------

// Produce a classic `hexdump -C` style rendering of a byte buffer.
std::string hexdump(const uint8_t* data, size_t len);

}  // namespace ntptool
