#include <cstdio>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "ntptool/commands.hpp"
#include "ntptool/ntp_client.hpp"
#include "ntptool/output.hpp"
#include "ntptool/util.hpp"

namespace ntptool {
namespace {

struct Hop {
    int index = 0;
    std::string query_target;
    std::string address;
    bool reachable = false;
    int stratum = 0;
    std::string refid;
    double offset = 0.0;
    double delay = 0.0;
    std::string note;
};

bool looks_like_ipv4(const std::string& s) {
    unsigned a, b, c, d;
    char extra;
    return std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) == 4;
}

}  // namespace

int cmd_trace(const Options& opt) {
    if (opt.hosts.empty()) {
        std::cerr << "trace: no host given\n";
        return 2;
    }
    const std::string start = opt.hosts.front();
    const Colorizer& c = opt.color;

    NtpClient client;
    QueryConfig cfg = make_query_config(opt);

    std::vector<Hop> hops;
    std::set<std::string> visited;
    std::string target = start;

    for (int i = 0; i < opt.max_hops; ++i) {
        if (interrupted()) break;
        Hop hop;
        hop.index = i;
        hop.query_target = target;

        std::string err;
        auto eps = resolve(target, opt.port, opt.family, err);
        if (eps.empty()) {
            hop.note = "resolve failed: " + err;
            hops.push_back(hop);
            break;
        }
        Endpoint ep = eps.front();
        hop.address = ep.to_string();

        // Loop detection on the resolved IP.
        std::string ipkey = ep.ip();
        if (visited.count(ipkey)) {
            hop.note = "loop detected (already visited " + ipkey + ")";
            hops.push_back(hop);
            break;
        }
        visited.insert(ipkey);

        QueryResult r = client.query(ep, cfg);
        if (!r.success || !r.time_valid) {
            hop.note = "no usable response: " + r.error;
            hops.push_back(hop);
            break;
        }

        hop.reachable = true;
        hop.stratum = r.response.stratum;
        hop.refid = r.response.refid_string();
        hop.offset = r.offset;
        hop.delay = r.delay;
        hops.push_back(hop);

        if (r.response.stratum <= 1) {
            // Reached a primary server (reference clock in refid).
            break;
        }

        // For stratum >= 2 the reference id is the upstream server's IPv4
        // address (only meaningful for IPv4 associations).
        std::string next = r.response.refid_string();
        if (!looks_like_ipv4(next) || next == "0.0.0.0") {
            hops.back().note =
                "upstream not an IPv4 refid (" + next + "); cannot follow";
            break;
        }
        target = next;
    }

    // ---- Output -----------------------------------------------------------
    if (opt.format == OutputFormat::Json) {
        std::cout << "{\n  \"start\": \"" << json_escape(start)
                  << "\",\n  \"hops\": [\n";
        for (size_t i = 0; i < hops.size(); ++i) {
            const Hop& h = hops[i];
            std::ostringstream js;
            js.setf(std::ios::fixed);
            js << "    {\"hop\": " << h.index << ", \"target\": \""
               << json_escape(h.query_target) << "\", \"address\": \""
               << json_escape(h.address) << "\", \"reachable\": "
               << (h.reachable ? "true" : "false");
            if (h.reachable)
                js << ", \"stratum\": " << h.stratum << ", \"refid\": \""
                   << json_escape(h.refid) << "\", \"offset_ms\": " << h.offset * 1e3
                   << ", \"delay_ms\": " << h.delay * 1e3;
            if (!h.note.empty()) js << ", \"note\": \"" << json_escape(h.note) << "\"";
            js << "}";
            std::cout << js.str() << (i + 1 < hops.size() ? ",\n" : "\n");
        }
        std::cout << "  ]\n}\n";
        return hops.empty() ? 1 : 0;
    }

    std::cout << c.bold("Tracing NTP hierarchy from ") << start << "\n\n";
    for (const Hop& h : hops) {
        std::ostringstream ln;
        ln << "  " << c.dim(std::to_string(h.index) + ".") << " ";
        if (h.reachable) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                          "stratum %-2d  %-22s  refid=%-16s  offset=%+.3f ms  delay=%.3f ms",
                          h.stratum, h.address.c_str(), h.refid.c_str(),
                          h.offset * 1e3, h.delay * 1e3);
            std::string s = buf;
            if (h.stratum <= 1) s = c.green(s);
            ln << s;
        } else {
            ln << c.red(h.query_target + "  — " + h.note);
        }
        std::cout << ln.str() << "\n";
        if (h.reachable && !h.note.empty())
            std::cout << "        " << c.dim(h.note) << "\n";
    }

    // Conclusion.
    if (!hops.empty() && hops.back().reachable && hops.back().stratum <= 1)
        std::cout << "\n"
                  << c.green("Reached stratum " +
                             std::to_string(hops.back().stratum) +
                             " (primary reference: " + hops.back().refid + ").")
                  << "\n";
    else
        std::cout << "\n" << c.yellow("Trace ended before reaching stratum 1.")
                  << "\n";
    return 0;
}

}  // namespace ntptool
