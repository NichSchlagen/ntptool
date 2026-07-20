#pragma once

// -----------------------------------------------------------------------------
// Command-line parsing and the shared Options structure consumed by every
// subcommand.
// -----------------------------------------------------------------------------

#include <chrono>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "ntptool/ntp_client.hpp"
#include "ntptool/output.hpp"
#include "ntptool/udp_socket.hpp"

namespace ntptool {

enum class Command {
    None,
    Help,
    Version,
    Query,
    Monitor,
    Compare,
    Scan,
    Control,
    Security,
    Trace,
    SelfTest,
};

enum class OutputFormat { Text, Json, Csv };

struct Options {
    Command command = Command::None;
    std::vector<std::string> hosts;

    // Transport / protocol.
    uint16_t port = 123;
    IpFamily family = IpFamily::Auto;
    uint8_t ntp_version = 4;
    std::chrono::milliseconds timeout{2000};
    int retries = 0;

    // Sampling / iteration.
    int count = 4;          // samples (query) / polls (monitor); 0 = infinite
    double interval = 1.0;  // seconds between samples

    // Output.
    OutputFormat format = OutputFormat::Text;
    bool no_color = false;
    bool color_forced = false;
    int verbose = 0;
    Colorizer color;        // resolved after parsing

    // Help topic (when command == Help).
    Command help_topic = Command::None;

    // Authentication.
    AuthType auth_type = AuthType::None;
    uint32_t key_id = 0;
    std::string key;

    // Scan.
    std::string file;
    int jobs = 16;

    // Control (mode 6).
    std::string control_vars;
    long assoc_id = 0;
    bool list_assoc = false;

    // Trace.
    int max_hops = 12;

    // Parse bookkeeping.
    bool show_help = false;
    std::string error;
};

// Parse argv. Returns false and sets opt.error on failure.
bool parse_cli(int argc, char** argv, Options& opt);

// Build a QueryConfig from the parsed options (with resolved auth key material).
QueryConfig make_query_config(const Options& opt);

void print_usage(std::ostream& os);
void print_command_help(std::ostream& os, Command cmd);
void print_version(std::ostream& os);

}  // namespace ntptool
