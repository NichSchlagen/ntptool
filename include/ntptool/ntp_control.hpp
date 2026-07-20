#pragma once

// -----------------------------------------------------------------------------
// NTP mode-6 control protocol (RFC 1305 App. B) — the mechanism used by ntpq to
// read system and peer variables and to enumerate associations.
// -----------------------------------------------------------------------------

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "ntptool/udp_socket.hpp"

namespace ntptool {

// Control opcodes.
enum : uint8_t {
    kCtlOpReadStat = 1,   // read status / association list (assoc == 0)
    kCtlOpReadVar = 2,    // read variables
    kCtlOpWriteVar = 3,
    kCtlOpReadClock = 4,
};

struct ControlConfig {
    uint8_t version = 2;  // ntpq speaks control version 2
    std::chrono::milliseconds timeout{2000};
    int max_fragments = 32;
};

struct ControlResponse {
    bool success = false;
    std::string error;

    bool response_bit = false;
    bool error_bit = false;
    bool more_bit = false;
    uint8_t opcode = 0;
    uint16_t status = 0;
    uint16_t assoc_id = 0;
    int fragments = 0;

    std::vector<uint8_t> data;  // reassembled payload

    std::string data_text() const {
        return std::string(data.begin(), data.end());
    }
};

struct AssocEntry {
    uint16_t assoc_id = 0;
    uint16_t peer_status = 0;
};

class NtpControlClient {
public:
    // Low-level request/response with fragment reassembly.
    ControlResponse request(const Endpoint& server, uint8_t opcode,
                            uint16_t assoc_id, const std::string& payload,
                            const ControlConfig& cfg);

    // Read variables (assoc_id 0 → system variables). `vars` is an optional
    // comma-separated list of variable names to request.
    ControlResponse read_variables(const Endpoint& server, uint16_t assoc_id,
                                   const std::string& vars,
                                   const ControlConfig& cfg);

    // Read the association list (peers) from the server.
    ControlResponse read_associations(const Endpoint& server,
                                       const ControlConfig& cfg);
};

// Parse "name=value, name=value, flag, ..." text into ordered key/value pairs.
std::vector<std::pair<std::string, std::string>> parse_ntp_vars(
    const std::string& text);

// Parse an association list payload into (assoc-id, peer-status) entries.
std::vector<AssocEntry> parse_assoc_list(const std::vector<uint8_t>& data);

// Decode a peer status word into a short human-readable summary.
std::string peer_status_string(uint16_t status);

}  // namespace ntptool
