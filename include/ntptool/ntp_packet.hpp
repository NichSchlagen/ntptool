#pragma once

// -----------------------------------------------------------------------------
// NTP association-mode packet (RFC 5905). Modes 1-5; the 48-byte fixed header
// plus an optional authenticator (key id + MAC).
// -----------------------------------------------------------------------------

#include <cstdint>
#include <string>
#include <vector>

#include "ntptool/ntp_time.hpp"

namespace ntptool {

enum class LeapIndicator : uint8_t {
    NoWarning = 0,       // in sync, no leap pending
    Add = 1,             // last minute of the day has 61 seconds
    Sub = 2,             // last minute of the day has 59 seconds
    Unsynchronized = 3,  // clock not synchronised (alarm)
};

enum class NtpMode : uint8_t {
    Reserved = 0,
    SymActive = 1,
    SymPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    Control = 6,
    Private = 7,
};

const char* leap_to_string(LeapIndicator li);
const char* mode_to_string(NtpMode m);

// The fixed 48-byte NTP header plus optional MAC.
struct NtpPacket {
    LeapIndicator leap = LeapIndicator::NoWarning;
    uint8_t version = 4;
    NtpMode mode = NtpMode::Client;
    uint8_t stratum = 0;
    int8_t poll = 0;           // log2 seconds
    int8_t precision = 0;      // log2 seconds
    uint32_t root_delay = 0;   // NTP short (16.16)
    uint32_t root_dispersion = 0;
    uint32_t reference_id = 0;  // 4 bytes, MSB = first wire byte
    NtpTime reference_ts;
    NtpTime originate_ts;
    NtpTime receive_ts;
    NtpTime transmit_ts;

    // Optional authenticator.
    bool has_mac = false;
    uint32_t key_id = 0;
    std::vector<uint8_t> mac;

    // Serialise the 48-byte header (and MAC, if present) to wire format.
    std::vector<uint8_t> serialize() const;

    // Parse a received datagram. Returns false when the buffer is too small.
    static bool parse(const uint8_t* data, size_t len, NtpPacket& out);

    // Interpretations / helpers ----------------------------------------------
    double root_delay_seconds() const { return ntp_short_to_seconds(root_delay); }
    double root_dispersion_seconds() const { return ntp_short_to_seconds(root_dispersion); }

    // Stratum 0 (KoD) or stratum 1: the 4-byte reference id is an ASCII code.
    bool refid_is_ascii() const { return stratum <= 1; }

    // Render the reference id: ASCII for stratum 0/1, dotted IPv4 for stratum
    // 2..15 (NTPv4/IPv4). For IPv6 upstreams the value is a 32-bit hash and is
    // shown as hex.
    std::string refid_string() const;

    // The 4-byte reference id as an ASCII code (trailing NULs trimmed).
    std::string refid_ascii() const;

    // Kiss-o'-Death: stratum == 0 and mode == server.
    bool is_kiss_of_death() const {
        return stratum == 0 && mode == NtpMode::Server;
    }
};

}  // namespace ntptool
