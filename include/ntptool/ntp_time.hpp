#pragma once

// -----------------------------------------------------------------------------
// NTP timestamp arithmetic (RFC 5905, section 6).
//
// An NTP "long" timestamp is a 64-bit unsigned fixed-point number: the upper 32
// bits count seconds since the prime epoch (1900-01-01 00:00:00 UTC) and the
// lower 32 bits are a binary fraction of a second (resolution ~232 ps).
//
// An NTP "short" timestamp (used for root delay / dispersion) is a 32-bit
// unsigned 16.16 fixed-point number of seconds.
// -----------------------------------------------------------------------------

#include <cstdint>
#include <string>

namespace ntptool {

// Seconds between the NTP epoch (1900) and the UNIX epoch (1970).
inline constexpr uint64_t kNtpUnixDeltaSeconds = 2208988800ULL;

// 2^32 as a double, used to scale the fractional part.
inline constexpr double kTwoPow32 = 4294967296.0;

// A 64-bit NTP timestamp (seconds:fraction).
struct NtpTime {
    uint64_t raw = 0;

    uint32_t seconds() const { return static_cast<uint32_t>(raw >> 32); }
    uint32_t fraction() const { return static_cast<uint32_t>(raw & 0xFFFFFFFFu); }
    bool is_zero() const { return raw == 0; }
};

// Current wall-clock time as an NTP timestamp (era 0, valid until 2036).
NtpTime ntp_now();

// Convert an NTP timestamp to seconds since the UNIX epoch (may be negative for
// timestamps before 1970). Uses era-0 interpretation.
double ntp_to_unix(NtpTime t);

// Convert seconds since the UNIX epoch to an NTP timestamp.
NtpTime unix_to_ntp(double unix_seconds);

// Signed difference (a - b) expressed in seconds. Correct across a single era
// rollover because the subtraction is performed in the wrapping 64-bit domain
// before being reinterpreted as a signed quantity — valid for any real
// difference below ~68 years, which always holds for measurement deltas.
double ntp_diff_seconds(NtpTime a, NtpTime b);

// Interpret an NTP "short" (16.16) value as seconds.
inline double ntp_short_to_seconds(uint32_t v) {
    return static_cast<double>(v) / 65536.0;
}

// Format an NTP timestamp as an ISO-8601 UTC string.
std::string ntp_to_iso8601(NtpTime t);

}  // namespace ntptool
