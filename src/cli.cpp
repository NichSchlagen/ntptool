#include "ntptool/cli.hpp"

#include <cstdlib>

#include "ntptool/util.hpp"
#include "ntptool/version.hpp"

namespace ntptool {
namespace {

Command parse_command(const std::string& s, bool& ok) {
    ok = true;
    std::string l = to_lower(s);
    if (l == "query" || l == "q") return Command::Query;
    if (l == "monitor" || l == "mon" || l == "watch") return Command::Monitor;
    if (l == "compare" || l == "cmp" || l == "diff") return Command::Compare;
    if (l == "scan") return Command::Scan;
    if (l == "control" || l == "ctl" || l == "rv" || l == "ntpq")
        return Command::Control;
    if (l == "security" || l == "sec" || l == "audit") return Command::Security;
    if (l == "trace") return Command::Trace;
    if (l == "selftest" || l == "test") return Command::SelfTest;
    if (l == "help" || l == "--help" || l == "-h") return Command::Help;
    if (l == "version" || l == "--version" || l == "-v") return Command::Version;
    ok = false;
    return Command::None;
}

bool to_int(const std::string& s, long& out) {
    try {
        size_t pos = 0;
        out = std::stol(s, &pos, 0);
        return pos == s.size();
    } catch (...) {
        return false;
    }
}

bool to_double(const std::string& s, double& out) {
    try {
        size_t pos = 0;
        out = std::stod(s, &pos);
        return pos == s.size();
    } catch (...) {
        return false;
    }
}

}  // namespace

bool parse_cli(int argc, char** argv, Options& opt) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        opt.command = Command::Help;
        return true;
    }

    size_t idx = 0;
    bool cmd_ok = false;
    Command c = parse_command(args[0], cmd_ok);
    if (cmd_ok) {
        opt.command = c;
        idx = 1;
    } else {
        // No explicit command; assume `query` (host may follow as positional).
        opt.command = Command::Query;
        idx = 0;
    }

    std::string cur;  // holds the consumed option value
    size_t i = idx;

    auto value = [&](const char* name) -> bool {
        if (i + 1 >= args.size()) {
            opt.error = std::string("option '") + name + "' requires a value";
            return false;
        }
        cur = args[++i];
        return true;
    };

    while (i < args.size()) {
        const std::string a = args[i];
        long iv = 0;
        double dv = 0.0;

        if (a == "-h" || a == "--help") {
            opt.show_help = true;
        } else if (a == "--version") {
            opt.command = Command::Version;
        } else if (a == "-p" || a == "--port") {
            if (!value("--port")) return false;
            if (!to_int(cur, iv) || iv < 1 || iv > 65535) {
                opt.error = "invalid port: " + cur;
                return false;
            }
            opt.port = static_cast<uint16_t>(iv);
        } else if (a == "-4" || a == "--ipv4") {
            opt.family = IpFamily::IPv4;
        } else if (a == "-6" || a == "--ipv6") {
            opt.family = IpFamily::IPv6;
        } else if (a == "-t" || a == "--timeout") {
            if (!value("--timeout")) return false;
            if (!to_int(cur, iv) || iv < 1) {
                opt.error = "invalid timeout (ms): " + cur;
                return false;
            }
            opt.timeout = std::chrono::milliseconds(iv);
        } else if (a == "-r" || a == "--retries") {
            if (!value("--retries")) return false;
            if (!to_int(cur, iv) || iv < 0) {
                opt.error = "invalid retries: " + cur;
                return false;
            }
            opt.retries = static_cast<int>(iv);
        } else if (a == "-c" || a == "--count") {
            if (!value("--count")) return false;
            if (!to_int(cur, iv) || iv < 0) {
                opt.error = "invalid count: " + cur;
                return false;
            }
            opt.count = static_cast<int>(iv);
        } else if (a == "-i" || a == "--interval") {
            if (!value("--interval")) return false;
            if (!to_double(cur, dv) || dv < 0.0) {
                opt.error = "invalid interval (seconds): " + cur;
                return false;
            }
            opt.interval = dv;
        } else if (a == "-f" || a == "--format") {
            if (!value("--format")) return false;
            std::string f = to_lower(cur);
            if (f == "text") opt.format = OutputFormat::Text;
            else if (f == "json") opt.format = OutputFormat::Json;
            else if (f == "csv") opt.format = OutputFormat::Csv;
            else {
                opt.error = "invalid format (text|json|csv): " + cur;
                return false;
            }
        } else if (a == "--no-color") {
            opt.no_color = true;
        } else if (a == "--color") {
            opt.color_forced = true;
            opt.no_color = false;
        } else if (a == "-v" || a == "--verbose") {
            opt.verbose++;
        } else if (a == "-vv") {
            opt.verbose += 2;
        } else if (a == "--ntp-version") {
            if (!value("--ntp-version")) return false;
            if (!to_int(cur, iv) || iv < 1 || iv > 4) {
                opt.error = "invalid NTP version (1-4): " + cur;
                return false;
            }
            opt.ntp_version = static_cast<uint8_t>(iv);
        } else if (a == "--key-id") {
            if (!value("--key-id")) return false;
            if (!to_int(cur, iv) || iv < 0) {
                opt.error = "invalid key id: " + cur;
                return false;
            }
            opt.key_id = static_cast<uint32_t>(iv);
        } else if (a == "--key") {
            if (!value("--key")) return false;
            opt.key = cur;
        } else if (a == "--auth") {
            if (!value("--auth")) return false;
            std::string t = to_lower(cur);
            if (t == "none") opt.auth_type = AuthType::None;
            else if (t == "md5") opt.auth_type = AuthType::MD5;
            else if (t == "sha1" || t == "sha") opt.auth_type = AuthType::SHA1;
            else {
                opt.error = "invalid auth type (md5|sha1): " + cur;
                return false;
            }
        } else if (a == "--file") {
            if (!value("--file")) return false;
            opt.file = cur;
        } else if (a == "-j" || a == "--jobs") {
            if (!value("--jobs")) return false;
            if (!to_int(cur, iv) || iv < 1 || iv > 1024) {
                opt.error = "invalid jobs (1-1024): " + cur;
                return false;
            }
            opt.jobs = static_cast<int>(iv);
        } else if (a == "--vars") {
            if (!value("--vars")) return false;
            opt.control_vars = cur;
        } else if (a == "--assoc") {
            if (!value("--assoc")) return false;
            if (!to_int(cur, iv) || iv < 0 || iv > 65535) {
                opt.error = "invalid association id: " + cur;
                return false;
            }
            opt.assoc_id = iv;
        } else if (a == "--list") {
            opt.list_assoc = true;
        } else if (a == "--max-hops") {
            if (!value("--max-hops")) return false;
            if (!to_int(cur, iv) || iv < 1 || iv > 64) {
                opt.error = "invalid max-hops (1-64): " + cur;
                return false;
            }
            opt.max_hops = static_cast<int>(iv);
        } else if (a.size() >= 2 && a[0] == '-' &&
                   !(a[1] >= '0' && a[1] <= '9')) {
            opt.error = "unknown option: " + a;
            return false;
        } else {
            // Positional argument: a host (or help topic).
            opt.hosts.push_back(a);
        }
        ++i;
    }

    // Resolve a help topic if the first positional names a command.
    if (opt.command == Command::Help && !opt.hosts.empty()) {
        bool ok = false;
        Command topic = parse_command(opt.hosts.front(), ok);
        if (ok) opt.help_topic = topic;
    }

    return true;
}

QueryConfig make_query_config(const Options& opt) {
    QueryConfig cfg;
    cfg.version = opt.ntp_version;
    cfg.timeout = opt.timeout;
    cfg.retries = opt.retries;
    cfg.capture_raw = opt.verbose >= 2;
    cfg.auth.type = opt.auth_type;
    cfg.auth.key_id = opt.key_id;
    cfg.auth.key.assign(opt.key.begin(), opt.key.end());
    return cfg;
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------

void print_version(std::ostream& os) {
    os << NTPTOOL_NAME << " " << NTPTOOL_VERSION
       << " — comprehensive NTP server testing toolkit\n";
}

void print_usage(std::ostream& os) {
    print_version(os);
    os <<
        "\n"
        "USAGE\n"
        "  ntptool <command> [options] [host ...]\n"
        "  ntptool <host>                 (shorthand for: ntptool query <host>)\n"
        "\n"
        "COMMANDS\n"
        "  query      Query one or more servers, show offset/delay and stats\n"
        "  monitor    Continuously poll a server and track live statistics\n"
        "  compare    Query several servers side by side, flag outliers\n"
        "  scan       Sweep many hosts/IPs to find reachable NTP servers\n"
        "  control    Read mode-6 system/peer variables (ntpq-style)\n"
        "  security   Audit a server (KoD, mode 6/7 amplification, monlist)\n"
        "  trace      Follow the reference-id chain toward stratum 1\n"
        "  selftest   Run internal self-tests (crypto, timestamp math)\n"
        "  help       Show help; `help <command>` for command details\n"
        "  version    Print version information\n"
        "\n"
        "GLOBAL OPTIONS\n"
        "  -p, --port <n>          UDP port (default 123)\n"
        "  -4, --ipv4 / -6,--ipv6  Force IPv4 or IPv6\n"
        "  -t, --timeout <ms>      Receive timeout per query (default 2000)\n"
        "  -r, --retries <n>       Retries after a timeout (default 0)\n"
        "  -c, --count <n>         Samples/polls (0 = infinite where allowed)\n"
        "  -i, --interval <sec>    Delay between samples (default 1.0)\n"
        "      --ntp-version <n>   NTP protocol version 1-4 (default 4)\n"
        "  -f, --format <fmt>      Output: text | json | csv (default text)\n"
        "      --color/--no-color  Force / disable ANSI colours\n"
        "  -v, --verbose           Increase verbosity (repeatable; -vv hexdump)\n"
        "      --auth <md5|sha1>   Symmetric-key auth; use with --key/--key-id\n"
        "      --key <secret>      Authentication key (ASCII)\n"
        "      --key-id <n>        Authentication key identifier\n"
        "  -h, --help              Show help\n"
        "\n"
        "EXAMPLES\n"
        "  ntptool query pool.ntp.org -c 8\n"
        "  ntptool compare 0.pool.ntp.org 1.pool.ntp.org time.google.com\n"
        "  ntptool monitor time.cloudflare.com -i 2\n"
        "  ntptool scan --file targets.txt -j 64 -f csv\n"
        "  ntptool control time.example.com --list\n"
        "  ntptool security ntp.example.net\n"
        "  ntptool trace 2.pool.ntp.org\n";
}

void print_command_help(std::ostream& os, Command cmd) {
    switch (cmd) {
        case Command::Query:
            os << "query — measure clock offset and delay against a server\n\n"
                  "  ntptool query [options] <host> [host ...]\n\n"
                  "Sends -c samples (default 4) spaced by -i seconds and reports\n"
                  "per-sample offset/delay plus aggregate statistics (min/max/mean/\n"
                  "median/stddev/jitter). Multiple hosts are queried in sequence.\n\n"
                  "  -c <n>   number of samples        -i <sec> spacing\n"
                  "  --auth md5 --key <k> --key-id <n>  authenticated query\n"
                  "  -f json|csv  machine-readable output\n";
            break;
        case Command::Monitor:
            os << "monitor — continuous live monitoring of one server\n\n"
                  "  ntptool monitor [options] <host>\n\n"
                  "Polls every -i seconds until -c polls are done (0 = until\n"
                  "Ctrl-C) and prints a live line per poll with a rolling summary.\n";
            break;
        case Command::Compare:
            os << "compare — query several servers and compare them\n\n"
                  "  ntptool compare [options] <host> <host> [host ...]\n\n"
                  "Takes -c samples of each host, prints a sorted table of median\n"
                  "offset/delay/stratum and flags servers whose offset deviates\n"
                  "from the group median (possible falsetickers).\n";
            break;
        case Command::Scan:
            os << "scan — discover reachable NTP servers\n\n"
                  "  ntptool scan [options] <host|IPv4/CIDR> ...\n"
                  "  ntptool scan --file targets.txt\n\n"
                  "Probes each target once with a short timeout using -j parallel\n"
                  "workers. Accepts hostnames, IPs and IPv4 CIDR ranges (e.g.\n"
                  "192.0.2.0/28). Use -f csv for scripting.\n";
            break;
        case Command::Control:
            os << "control — read mode-6 variables (like ntpq)\n\n"
                  "  ntptool control [options] <host>\n\n"
                  "  --list            enumerate associations (peers)\n"
                  "  --assoc <id>      read variables of a specific association\n"
                  "  --vars <a,b,c>    request only the named variables\n\n"
                  "Many public servers restrict mode 6; a timeout usually means\n"
                  "queries are (correctly) blocked.\n";
            break;
        case Command::Security:
            os << "security — audit a server's exposure\n\n"
                  "  ntptool security [options] <host>\n\n"
                  "Checks synchronisation state and leap status, and tests for\n"
                  "amplification vectors: classic mode-7 monlist (CVE-2013-5211),\n"
                  "mode-6 readvar reflection, and reports amplification factors.\n";
            break;
        case Command::Trace:
            os << "trace — walk the server hierarchy toward stratum 1\n\n"
                  "  ntptool trace [options] <host>\n\n"
                  "Queries the server, then follows its IPv4 reference id upstream\n"
                  "hop by hop until stratum 1, a loop, or --max-hops is reached.\n";
            break;
        case Command::SelfTest:
            os << "selftest — validate internal algorithms\n\n"
                  "  ntptool selftest\n\n"
                  "Runs known-answer tests for MD5, SHA-1 and NTP timestamp math.\n";
            break;
        default:
            print_usage(os);
            break;
    }
}

}  // namespace ntptool
