#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "ntptool/commands.hpp"
#include "ntptool/output.hpp"
#include "ntptool/statistics.hpp"
#include "ntptool/util.hpp"

namespace ntptool {
namespace {

struct HostSummary {
    std::string host;
    std::string address;
    bool reachable = false;
    int stratum = 0;
    std::string refid;
    double offset = 0.0;   // median
    double delay = 0.0;    // median
    double jitter = 0.0;
    int loss = 0;
    int samples = 0;
    bool outlier = false;
    std::string note;
};

void sleep_seconds(double s) {
    if (s > 0) std::this_thread::sleep_for(std::chrono::duration<double>(s));
}

double median_of(std::vector<double> v) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t m = v.size() / 2;
    return (v.size() % 2 == 0) ? (v[m - 1] + v[m]) / 2.0 : v[m];
}

}  // namespace

int cmd_compare(const Options& opt) {
    if (opt.hosts.size() < 2) {
        std::cerr << "compare: need at least two hosts\n";
        return 2;
    }

    NtpClient client;
    QueryConfig cfg = make_query_config(opt);
    const Colorizer& c = opt.color;
    const int n = opt.count > 0 ? opt.count : 4;
    const double kOutlierThreshold = 0.100;  // 100 ms

    std::vector<HostSummary> rows;
    rows.reserve(opt.hosts.size());

    for (const std::string& host : opt.hosts) {
        if (interrupted()) break;
        HostSummary hs;
        hs.host = host;

        std::string err;
        auto eps = resolve(host, opt.port, opt.family, err);
        if (eps.empty()) {
            hs.note = err;
            rows.push_back(hs);
            continue;
        }
        Endpoint ep = eps.front();
        hs.address = ep.to_string();

        Series off, del;
        for (int s = 0; s < n; ++s) {
            if (interrupted()) break;
            QueryResult r = client.query(ep, cfg);
            if (r.success && r.time_valid) {
                off.add(r.offset);
                del.add(r.delay);
                hs.stratum = r.response.stratum;
                hs.refid = r.response.refid_string();
            } else {
                hs.loss++;
            }
            if (s + 1 < n) sleep_seconds(opt.interval);
        }
        hs.samples = n;
        if (!off.empty()) {
            hs.reachable = true;
            auto os = off.summary();
            hs.offset = os.median;
            hs.jitter = os.jitter;
            hs.delay = del.summary().median;
        } else if (hs.note.empty()) {
            hs.note = "no response";
        }
        rows.push_back(hs);
    }

    // Consensus: group median of reachable per-host offsets.
    std::vector<double> offs;
    for (const auto& r : rows)
        if (r.reachable) offs.push_back(r.offset);
    double consensus = median_of(offs);

    for (auto& r : rows) {
        if (r.reachable && std::fabs(r.offset - consensus) > kOutlierThreshold) {
            r.outlier = true;
            r.note = "OUTLIER (>" +
                     std::to_string(static_cast<int>(kOutlierThreshold * 1e3)) +
                     "ms from consensus)";
        }
    }

    // Sort: reachable first, then by offset.
    std::sort(rows.begin(), rows.end(), [](const HostSummary& a, const HostSummary& b) {
        if (a.reachable != b.reachable) return a.reachable > b.reachable;
        return a.offset < b.offset;
    });

    // ---- Output -----------------------------------------------------------
    if (opt.format == OutputFormat::Csv) {
        std::cout << "host,address,reachable,stratum,refid,offset_ms,delay_ms,"
                     "jitter_ms,loss,samples,outlier,note\n";
        for (const auto& r : rows) {
            std::cout << csv_escape(r.host) << "," << csv_escape(r.address) << ","
                      << (r.reachable ? 1 : 0) << "," << r.stratum << ","
                      << csv_escape(r.refid) << ",";
            char b[64];
            if (r.reachable) {
                std::snprintf(b, sizeof(b), "%.3f,%.3f,%.3f", r.offset * 1e3,
                              r.delay * 1e3, r.jitter * 1e3);
                std::cout << b;
            } else {
                std::cout << ",,";
            }
            std::cout << "," << r.loss << "," << r.samples << ","
                      << (r.outlier ? 1 : 0) << "," << csv_escape(r.note) << "\n";
        }
        return 0;
    }

    if (opt.format == OutputFormat::Json) {
        std::cout << "{\n  \"consensus_offset_ms\": " << consensus * 1e3
                  << ",\n  \"servers\": [\n";
        for (size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];
            std::ostringstream js;
            js.setf(std::ios::fixed);
            js << "    {\"host\": \"" << json_escape(r.host) << "\", \"address\": \""
               << json_escape(r.address) << "\", \"reachable\": "
               << (r.reachable ? "true" : "false");
            if (r.reachable)
                js << ", \"stratum\": " << r.stratum << ", \"refid\": \""
                   << json_escape(r.refid) << "\", \"offset_ms\": " << r.offset * 1e3
                   << ", \"delay_ms\": " << r.delay * 1e3
                   << ", \"jitter_ms\": " << r.jitter * 1e3;
            js << ", \"loss\": " << r.loss << ", \"outlier\": "
               << (r.outlier ? "true" : "false");
            if (!r.note.empty()) js << ", \"note\": \"" << json_escape(r.note) << "\"";
            js << "}";
            std::cout << js.str() << (i + 1 < rows.size() ? ",\n" : "\n");
        }
        std::cout << "  ]\n}\n";
        return 0;
    }

    // Text table.
    std::cout << c.bold("Comparing ") << rows.size() << " servers ("
              << n << " samples each). Consensus offset: "
              << format_ms_signed(consensus) << "\n\n";
    char hdr[256];
    std::snprintf(hdr, sizeof(hdr), "  %-28s %-22s %3s %12s %10s %8s %6s",
                  "HOST", "ADDRESS", "STR", "OFFSET(ms)", "DELAY(ms)", "JIT(ms)",
                  "LOSS");
    std::cout << c.dim(hdr) << "\n";

    for (const auto& r : rows) {
        char line[512];
        std::string host = r.host.size() > 28 ? r.host.substr(0, 27) + "…" : r.host;
        std::string addr = r.address.size() > 22 ? r.address.substr(0, 21) + "…"
                                                  : r.address;
        if (r.reachable) {
            char loss[16];
            std::snprintf(loss, sizeof(loss), "%d/%d", r.loss, r.samples);
            std::snprintf(line, sizeof(line),
                          "  %-28s %-22s %3d %+12.3f %10.3f %8.3f %6s",
                          host.c_str(), addr.c_str(), r.stratum, r.offset * 1e3,
                          r.delay * 1e3, r.jitter * 1e3, loss);
            std::string s = line;
            if (r.outlier) s = c.red(s + "  ← " + r.note);
            std::cout << s << "\n";
        } else {
            std::snprintf(line, sizeof(line), "  %-28s %-22s %3s %s",
                          host.c_str(), addr.c_str(), "-",
                          ("unreachable: " + r.note).c_str());
            std::cout << c.dim(line) << "\n";
        }
    }
    std::cout << "\n";
    return 0;
}

}  // namespace ntptool
