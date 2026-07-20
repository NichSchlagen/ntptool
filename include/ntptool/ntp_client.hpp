#pragma once

// -----------------------------------------------------------------------------
// The NTP measurement engine: performs a client/server exchange and derives the
// clock offset, round-trip delay and related quality metrics per RFC 5905.
// -----------------------------------------------------------------------------

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "ntptool/ntp_packet.hpp"
#include "ntptool/ntp_time.hpp"
#include "ntptool/udp_socket.hpp"

namespace ntptool {

enum class AuthType { None, MD5, SHA1 };

const char* auth_type_name(AuthType t);

struct AuthConfig {
    AuthType type = AuthType::None;
    uint32_t key_id = 0;
    std::vector<uint8_t> key;  // raw key material (ASCII or decoded hex)
};

struct QueryConfig {
    uint8_t version = 4;
    std::chrono::milliseconds timeout{2000};
    int retries = 0;             // extra attempts after the first timeout
    AuthConfig auth;             // optional symmetric-key authentication
    bool capture_raw = false;    // keep raw request/response bytes (verbose)
};

struct QueryResult {
    bool success = false;        // a well-formed server response was received
    bool time_valid = false;     // offset/delay are meaningful
    std::string error;

    Endpoint server;
    NtpPacket response;

    // The four canonical timestamps.
    NtpTime t1;  // client transmit (originate)
    NtpTime t2;  // server receive
    NtpTime t3;  // server transmit
    NtpTime t4;  // client receive (destination)

    // Derived metrics (seconds).
    double offset = 0.0;         // local clock offset relative to the server
    double delay = 0.0;          // network round-trip delay
    double rtt = 0.0;            // measured wall-clock round trip (t4 - t1)
    double root_delay = 0.0;
    double root_dispersion = 0.0;
    double root_distance = 0.0;  // root_delay/2 + root_dispersion
    double precision_seconds = 0.0;

    // Server metadata (mirrored from the response for convenience).
    uint8_t stratum = 0;
    LeapIndicator leap = LeapIndicator::NoWarning;
    std::string refid;

    // Kiss-o'-Death.
    bool kiss_of_death = false;
    std::string kiss_code;

    // Authentication.
    bool auth_requested = false;
    bool auth_present = false;   // response carried a MAC
    bool auth_valid = false;     // MAC verified against the configured key

    // Raw bytes (only when capture_raw is set).
    std::vector<uint8_t> raw_request;
    std::vector<uint8_t> raw_response;
};

class NtpClient {
public:
    // Perform a single query against an already-resolved endpoint.
    QueryResult query(const Endpoint& server, const QueryConfig& cfg);

    // Resolve `host` and query the first usable address.
    QueryResult query_host(const std::string& host, uint16_t port,
                           IpFamily family, const QueryConfig& cfg);
};

// Compute an NTP symmetric-key MAC over `header` (48 bytes) with the given key.
std::vector<uint8_t> compute_ntp_mac(AuthType type,
                                     const std::vector<uint8_t>& key,
                                     const uint8_t* header, size_t header_len);

}  // namespace ntptool
