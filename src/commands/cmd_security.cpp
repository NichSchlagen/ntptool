#include <chrono>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "ntptool/commands.hpp"
#include "ntptool/ntp_client.hpp"
#include "ntptool/ntp_control.hpp"
#include "ntptool/output.hpp"
#include "ntptool/udp_socket.hpp"
#include "ntptool/util.hpp"

namespace ntptool {
namespace {

// Result of firing one crafted request and collecting all replies.
struct RawProbe {
    bool responded = false;
    int packets = 0;
    size_t response_bytes = 0;
    size_t request_bytes = 0;
    double amplification = 0.0;
    std::string error;
};

RawProbe raw_probe(const Endpoint& ep, const std::vector<uint8_t>& payload,
                   std::chrono::milliseconds timeout) {
    RawProbe pr;
    pr.request_bytes = payload.size();

    UdpSocket sock;
    std::string err;
    sock.set_recv_timeout(timeout);
    if (!sock.open(ep.family(), err)) {
        pr.error = err;
        return pr;
    }
    if (!sock.send_to(ep, payload.data(), payload.size(), err)) {
        pr.error = err;
        return pr;
    }

    // Collect every datagram that arrives until the socket times out.
    for (int i = 0; i < 2000; ++i) {
        std::vector<uint8_t> buf;
        Endpoint from;
        RecvStatus st = sock.recv_from(buf, from, err);
        if (st == RecvStatus::Ok) {
            pr.responded = true;
            pr.packets++;
            pr.response_bytes += buf.size();
            if (pr.response_bytes > 4 * 1024 * 1024) break;  // safety cap
        } else if (st == RecvStatus::Timeout) {
            break;
        } else {
            if (!pr.responded) pr.error = err;
            break;
        }
    }
    if (pr.request_bytes > 0)
        pr.amplification =
            static_cast<double>(pr.response_bytes) / static_cast<double>(pr.request_bytes);
    return pr;
}

std::vector<uint8_t> build_monlist_request() {
    // Classic mode-7 (ntpdc) MON_GETLIST_1 request — the CVE-2013-5211 probe.
    // byte0 = 0x17: response=0, more=0, version=2, mode=7
    // byte1 = 0x00: auth=0, sequence=0
    // byte2 = 0x03: implementation = IMPL_XNTPD
    // byte3 = 0x2a: request code 42 = REQ_MON_GETLIST_1
    return {0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00};
}

std::vector<uint8_t> build_mode6_readvar_request() {
    // Mode-6 read-variables of the system association (assoc id 0).
    std::vector<uint8_t> b;
    b.push_back(static_cast<uint8_t>((2 << 3) | 6));  // VN=2, Mode=6
    b.push_back(0x02);                                // opcode 2 (readvar)
    static std::mt19937 rng{std::random_device{}()};
    uint16_t seq = static_cast<uint16_t>(rng() & 0xFFFF);
    put_u16(b, seq);  // sequence
    put_u16(b, 0);    // status
    put_u16(b, 0);    // assoc id
    put_u16(b, 0);    // offset
    put_u16(b, 0);    // count
    return b;
}

enum class Sev { Ok, Info, Warn, High };

struct Finding {
    Sev sev;
    std::string check;
    std::string detail;
};

const char* sev_name(Sev s) {
    switch (s) {
        case Sev::Ok:   return "OK";
        case Sev::Info: return "INFO";
        case Sev::Warn: return "WARN";
        case Sev::High: return "HIGH";
    }
    return "?";
}

std::string sev_colored(const Colorizer& c, Sev s) {
    switch (s) {
        case Sev::Ok:   return c.green("[ OK ]");
        case Sev::Info: return c.cyan("[INFO]");
        case Sev::Warn: return c.yellow("[WARN]");
        case Sev::High: return c.red("[HIGH]");
    }
    return "[????]";
}

}  // namespace

int cmd_security(const Options& opt) {
    if (opt.hosts.empty()) {
        std::cerr << "security: no host given\n";
        return 2;
    }
    const std::string host = opt.hosts.front();
    const Colorizer& c = opt.color;

    std::string err;
    auto eps = resolve(host, opt.port, opt.family, err);
    if (eps.empty()) {
        std::cerr << "security: " << err << "\n";
        return 1;
    }
    Endpoint ep = eps.front();

    std::vector<Finding> findings;

    // ---- 1. Baseline synchronisation state --------------------------------
    NtpClient client;
    QueryConfig qcfg = make_query_config(opt);
    QueryResult q = client.query(ep, qcfg);

    std::string server_version;

    if (!q.success) {
        findings.push_back({Sev::Warn, "reachability",
                            "no valid NTP response: " + q.error});
    } else if (q.kiss_of_death) {
        findings.push_back({Sev::Info, "rate-limiting",
                            "server issued Kiss-o'-Death (" + q.kiss_code +
                                ") — rate limiting is active"});
    } else {
        std::ostringstream d;
        d << "stratum " << static_cast<int>(q.response.stratum) << ", refid "
          << q.response.refid_string() << ", offset " << format_ms_signed(q.offset);
        findings.push_back({Sev::Ok, "reachability", d.str()});

        if (q.response.leap == LeapIndicator::Unsynchronized ||
            q.response.stratum == 0 || q.response.stratum >= 16) {
            findings.push_back({Sev::Warn, "sync-state",
                                "server is NOT synchronised (clients would reject it)"});
        } else {
            findings.push_back({Sev::Ok, "sync-state",
                                std::string("synchronised, leap=") +
                                    leap_to_string(q.response.leap)});
        }
    }

    // ---- 2. Mode-7 monlist (CVE-2013-5211) --------------------------------
    RawProbe monlist = raw_probe(ep, build_monlist_request(), opt.timeout);
    if (monlist.responded) {
        std::ostringstream d;
        d.setf(std::ios::fixed);
        d << "server ANSWERED mode-7 monlist: " << monlist.packets
          << " packet(s), " << monlist.response_bytes << " bytes, "
          << "amplification x" << std::setprecision(1) << monlist.amplification
          << " — vulnerable to CVE-2013-5211 DDoS reflection";
        findings.push_back({Sev::High, "monlist", d.str()});
    } else if (!monlist.error.empty()) {
        findings.push_back({Sev::Info, "monlist",
                            "no monlist reply (" + monlist.error + ")"});
    } else {
        findings.push_back({Sev::Ok, "monlist",
                            "mode-7 monlist disabled / not answered (good)"});
    }

    // ---- 3. Mode-6 readvar reflection -------------------------------------
    RawProbe rv = raw_probe(ep, build_mode6_readvar_request(), opt.timeout);
    if (rv.responded) {
        // Try to extract the ntpd version string for the report.
        NtpControlClient ctl;
        ControlConfig ccfg;
        ccfg.timeout = opt.timeout;
        ControlResponse cr = ctl.read_variables(ep, 0, "", ccfg);
        if (cr.success) {
            for (auto& kv : parse_ntp_vars(cr.data_text()))
                if (iequals(kv.first, "version")) server_version = kv.second;
        }
        std::ostringstream d;
        d.setf(std::ios::fixed);
        d << "server answers unauthenticated mode-6 readvar: "
          << rv.response_bytes << " bytes, amplification x"
          << std::setprecision(1) << rv.amplification;
        if (!server_version.empty()) d << " (discloses: " << server_version << ")";
        d << " — usable for reflection/DDoS and info disclosure";
        findings.push_back({rv.amplification >= 3.0 ? Sev::High : Sev::Warn,
                            "mode6-readvar", d.str()});
    } else if (!rv.error.empty()) {
        findings.push_back({Sev::Info, "mode6-readvar",
                            "no mode-6 reply (" + rv.error + ")"});
    } else {
        findings.push_back({Sev::Ok, "mode6-readvar",
                            "mode-6 queries restricted / not answered (good)"});
    }

    // ---- Output -----------------------------------------------------------
    int high = 0, warn = 0;
    for (const auto& f : findings) {
        if (f.sev == Sev::High) ++high;
        if (f.sev == Sev::Warn) ++warn;
    }

    if (opt.format == OutputFormat::Json) {
        std::cout << "{\n  \"host\": \"" << json_escape(host)
                  << "\",\n  \"address\": \"" << json_escape(ep.to_string())
                  << "\",\n  \"high\": " << high << ",\n  \"warn\": " << warn
                  << ",\n  \"findings\": [\n";
        for (size_t i = 0; i < findings.size(); ++i)
            std::cout << "    {\"severity\": \"" << sev_name(findings[i].sev)
                      << "\", \"check\": \"" << json_escape(findings[i].check)
                      << "\", \"detail\": \"" << json_escape(findings[i].detail)
                      << "\"}" << (i + 1 < findings.size() ? ",\n" : "\n");
        std::cout << "  ]\n}\n";
        return high > 0 ? 1 : 0;
    }
    if (opt.format == OutputFormat::Csv) {
        std::cout << "severity,check,detail\n";
        for (const auto& f : findings)
            std::cout << sev_name(f.sev) << "," << csv_escape(f.check) << ","
                      << csv_escape(f.detail) << "\n";
        return high > 0 ? 1 : 0;
    }

    std::cout << c.bold("Security audit: ") << host << " (" << ep.to_string()
              << ")\n\n";
    for (const auto& f : findings)
        std::cout << "  " << sev_colored(c, f.sev) << " "
                  << c.bold(f.check) << ": " << f.detail << "\n";

    std::cout << "\n";
    if (high > 0)
        std::cout << c.red("Overall: " + std::to_string(high) +
                           " high-risk finding(s).")
                  << " This server should not be publicly exposed as-is.\n";
    else if (warn > 0)
        std::cout << c.yellow("Overall: no amplification vectors, but " +
                              std::to_string(warn) + " warning(s).")
                  << "\n";
    else
        std::cout << c.green("Overall: no amplification vectors detected.") << "\n";
    return high > 0 ? 1 : 0;
}

}  // namespace ntptool
