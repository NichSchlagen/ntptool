#include <algorithm>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "ntptool/commands.hpp"
#include "ntptool/output.hpp"
#include "ntptool/util.hpp"

namespace ntptool {
namespace {

constexpr size_t kMaxTargets = 100000;

struct ScanResult {
    std::string target;
    bool reachable = false;
    std::string address;
    int stratum = 0;
    std::string refid;
    double offset = 0.0;
    double delay = 0.0;
    std::string error;
};

bool parse_ipv4(const std::string& s, uint32_t& out) {
    unsigned a, b, cc, d;
    char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &cc, &d, &extra) != 4)
        return false;
    if (a > 255 || b > 255 || cc > 255 || d > 255) return false;
    out = (a << 24) | (b << 16) | (cc << 8) | d;
    return true;
}

std::string ipv4_to_string(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (v >> 24) & 0xFF,
                  (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
    return buf;
}

// Expand a single target token into concrete host strings. Supports plain
// hostnames/IPs and IPv4 CIDR notation (a.b.c.d/nn).
bool expand_target(const std::string& tok, std::vector<std::string>& out,
                   std::string& err) {
    size_t slash = tok.find('/');
    if (slash == std::string::npos) {
        out.push_back(tok);
        return true;
    }
    std::string base = tok.substr(0, slash);
    std::string plen = tok.substr(slash + 1);
    uint32_t ip;
    long prefix;
    if (!parse_ipv4(base, ip)) {
        err = "CIDR base is not an IPv4 address: " + base;
        return false;
    }
    try {
        prefix = std::stol(plen);
    } catch (...) {
        err = "invalid CIDR prefix: " + plen;
        return false;
    }
    if (prefix < 0 || prefix > 32) {
        err = "CIDR prefix out of range: " + plen;
        return false;
    }
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
    uint32_t network = ip & mask;
    uint64_t count = (prefix == 32) ? 1ull : (1ull << (32 - prefix));
    if (count > kMaxTargets) {
        err = "CIDR range too large (" + std::to_string(count) +
              " addresses; max " + std::to_string(kMaxTargets) + ")";
        return false;
    }
    for (uint64_t i = 0; i < count; ++i)
        out.push_back(ipv4_to_string(network + static_cast<uint32_t>(i)));
    return true;
}

}  // namespace

int cmd_scan(const Options& opt) {
    // ---- Gather targets ---------------------------------------------------
    std::vector<std::string> raw_tokens = opt.hosts;
    if (!opt.file.empty()) {
        std::ifstream in(opt.file);
        if (!in) {
            std::cerr << "scan: cannot open file: " << opt.file << "\n";
            return 2;
        }
        std::string line;
        while (std::getline(in, line)) {
            std::string t = trim(line);
            if (t.empty() || t[0] == '#') continue;
            // Allow multiple tokens per line.
            for (auto& piece : split(t, ' '))
                if (!trim(piece).empty()) raw_tokens.push_back(trim(piece));
        }
    }
    if (raw_tokens.empty()) {
        std::cerr << "scan: no targets (give hosts/CIDRs or --file)\n";
        return 2;
    }

    std::vector<std::string> targets;
    for (const auto& tok : raw_tokens) {
        std::string err;
        if (!expand_target(tok, targets, err)) {
            std::cerr << "scan: " << err << "\n";
            return 2;
        }
        if (targets.size() > kMaxTargets) {
            std::cerr << "scan: too many targets (max " << kMaxTargets << ")\n";
            return 2;
        }
    }

    const Colorizer& c = opt.color;
    const bool text = opt.format == OutputFormat::Text;
    if (text)
        std::cerr << "Scanning " << targets.size() << " target(s) with "
                  << opt.jobs << " workers...\n";

    // ---- Worker pool ------------------------------------------------------
    std::vector<ScanResult> results(targets.size());
    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    std::mutex progress_mtx;
    QueryConfig cfg = make_query_config(opt);

    auto worker = [&]() {
        NtpClient client;
        for (;;) {
            if (interrupted()) return;
            size_t idx = next.fetch_add(1);
            if (idx >= targets.size()) return;

            ScanResult sr;
            sr.target = targets[idx];

            std::string err;
            auto eps = resolve(targets[idx], opt.port, opt.family, err);
            if (eps.empty()) {
                sr.error = err;
            } else {
                QueryResult r = client.query(eps.front(), cfg);
                sr.address = eps.front().to_string();
                if (r.success) {
                    sr.reachable = true;
                    sr.stratum = r.response.stratum;
                    sr.refid = r.response.refid_string();
                    sr.offset = r.offset;
                    sr.delay = r.delay;
                    if (!r.time_valid && r.kiss_of_death)
                        sr.refid = "KoD:" + r.kiss_code;
                } else {
                    sr.error = r.error;
                }
            }
            results[idx] = std::move(sr);

            size_t d = ++done;
            if (text) {
                size_t step = std::max<size_t>(1, targets.size() / 100);
                if (d % step == 0 || d == targets.size()) {
                    std::lock_guard<std::mutex> lk(progress_mtx);
                    std::cerr << "\r  " << d << "/" << targets.size()
                              << " scanned" << std::flush;
                }
            }
        }
    };

    int nthreads = std::min<int>(opt.jobs, static_cast<int>(targets.size()));
    if (nthreads < 1) nthreads = 1;
    std::vector<std::thread> pool;
    for (int i = 0; i < nthreads; ++i) pool.emplace_back(worker);
    for (auto& t : pool) t.join();
    if (text) std::cerr << "\r" << std::string(40, ' ') << "\r";

    // ---- Report -----------------------------------------------------------
    size_t reachable = 0;
    for (const auto& r : results)
        if (r.reachable) ++reachable;

    if (opt.format == OutputFormat::Csv) {
        std::cout << "target,address,reachable,stratum,refid,offset_ms,delay_ms,"
                     "error\n";
        for (const auto& r : results) {
            std::cout << csv_escape(r.target) << "," << csv_escape(r.address)
                      << "," << (r.reachable ? 1 : 0) << ",";
            if (r.reachable) {
                char b[64];
                std::snprintf(b, sizeof(b), "%d,%s,%.3f,%.3f", r.stratum,
                              r.refid.c_str(), r.offset * 1e3, r.delay * 1e3);
                std::cout << b;
            } else {
                std::cout << ",,,";
            }
            std::cout << "," << csv_escape(r.error) << "\n";
        }
        return reachable > 0 ? 0 : 1;
    }

    if (opt.format == OutputFormat::Json) {
        std::cout << "{\n  \"scanned\": " << results.size()
                  << ",\n  \"reachable\": " << reachable
                  << ",\n  \"servers\": [\n";
        bool first = true;
        for (const auto& r : results) {
            if (!r.reachable && opt.verbose == 0) continue;
            std::ostringstream js;
            js.setf(std::ios::fixed);
            js << "    {\"target\": \"" << json_escape(r.target)
               << "\", \"reachable\": " << (r.reachable ? "true" : "false");
            if (r.reachable)
                js << ", \"address\": \"" << json_escape(r.address)
                   << "\", \"stratum\": " << r.stratum << ", \"refid\": \""
                   << json_escape(r.refid) << "\", \"offset_ms\": " << r.offset * 1e3
                   << ", \"delay_ms\": " << r.delay * 1e3;
            else if (!r.error.empty())
                js << ", \"error\": \"" << json_escape(r.error) << "\"";
            js << "}";
            std::cout << (first ? "" : ",\n") << js.str();
            first = false;
        }
        std::cout << "\n  ]\n}\n";
        return reachable > 0 ? 0 : 1;
    }

    // Text: sort reachable by stratum then offset.
    std::vector<const ScanResult*> sorted;
    for (const auto& r : results) sorted.push_back(&r);
    std::sort(sorted.begin(), sorted.end(), [](const ScanResult* a, const ScanResult* b) {
        if (a->reachable != b->reachable) return a->reachable > b->reachable;
        if (a->stratum != b->stratum) return a->stratum < b->stratum;
        return a->offset < b->offset;
    });

    char hdr[256];
    std::snprintf(hdr, sizeof(hdr), "  %-24s %-22s %3s %-16s %11s %10s",
                  "TARGET", "ADDRESS", "STR", "REFID", "OFFSET(ms)", "DELAY(ms)");
    std::cout << c.dim(hdr) << "\n";
    for (const ScanResult* r : sorted) {
        if (!r->reachable && opt.verbose == 0) continue;
        std::string tgt = r->target.size() > 24 ? r->target.substr(0, 23) + "…"
                                                : r->target;
        if (r->reachable) {
            char line[512];
            std::snprintf(line, sizeof(line),
                          "  %-24s %-22s %3d %-16s %+11.3f %10.3f", tgt.c_str(),
                          r->address.c_str(), r->stratum, r->refid.c_str(),
                          r->offset * 1e3, r->delay * 1e3);
            std::cout << c.green(line) << "\n";
        } else {
            char line[256];
            std::snprintf(line, sizeof(line), "  %-24s %s", tgt.c_str(),
                          ("unreachable: " + r->error).c_str());
            std::cout << c.dim(line) << "\n";
        }
    }
    std::cout << "\n"
              << c.bold("Result: ") << reachable << " of " << results.size()
              << " reachable.\n";
    return reachable > 0 ? 0 : 1;
}

}  // namespace ntptool
