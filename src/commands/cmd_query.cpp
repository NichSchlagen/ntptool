#include <chrono>
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

void sleep_seconds(double s) {
    if (s > 0) std::this_thread::sleep_for(std::chrono::duration<double>(s));
}

std::string ms3(double seconds) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.3f", seconds * 1e3);
    return buf;
}

void print_summary_line(std::ostream& os, const std::string& label,
                        const StatSummary& s, const Colorizer& c) {
    std::ostringstream v;
    v << "min/avg/median/max = " << ms3(s.min) << " / " << ms3(s.mean) << " / "
      << ms3(s.median) << " / " << ms3(s.max) << " ms";
    os << "  " << c.bold(label) << "  " << v.str() << "\n";
    os << "  " << std::string(label.size(), ' ') << "  stddev " << ms3(s.stddev)
       << " ms, jitter " << ms3(s.jitter) << " ms\n";
}

std::string stat_json(const std::string& key, const StatSummary& s, int indent) {
    std::string in(static_cast<size_t>(indent), ' ');
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os << in << "\"" << key << "\": {"
       << "\"n\": " << s.n << ", \"min\": " << s.min * 1e3
       << ", \"mean\": " << s.mean * 1e3 << ", \"median\": " << s.median * 1e3
       << ", \"max\": " << s.max * 1e3 << ", \"stddev\": " << s.stddev * 1e3
       << ", \"jitter\": " << s.jitter * 1e3 << "}";
    return os.str();
}

}  // namespace

int cmd_query(const Options& opt) {
    if (opt.hosts.empty()) {
        std::cerr << "query: no host given (try `ntptool help query`)\n";
        return 2;
    }

    NtpClient client;
    QueryConfig cfg = make_query_config(opt);
    const Colorizer& c = opt.color;
    const bool json = opt.format == OutputFormat::Json;
    const bool csv = opt.format == OutputFormat::Csv;
    const int n_samples = opt.count > 0 ? opt.count : 1;

    if (csv) std::cout << query_csv_header() << "\n";
    if (json) std::cout << "[\n";

    int exit_code = 0;
    bool first_host = true;

    for (const std::string& host : opt.hosts) {
        std::string err;
        auto eps = resolve(host, opt.port, opt.family, err);
        if (eps.empty()) {
            exit_code = 1;
            if (json) {
                if (!first_host) std::cout << ",\n";
                std::cout << "  {\"host\": \"" << json_escape(host)
                          << "\", \"success\": false, \"error\": \""
                          << json_escape(err) << "\"}";
                first_host = false;
            } else if (csv) {
                QueryResult r;
                r.error = err;
                std::cout << query_csv_row(host, r) << "\n";
            } else {
                std::cout << c.bold("== " + host + " ==") << "\n  "
                          << c.red("error: ") << err << "\n\n";
            }
            continue;
        }
        Endpoint ep = eps.front();

        Series off, del;
        int loss = 0;
        QueryResult last_good;
        bool have_good = false;
        std::vector<QueryResult> samples;
        samples.reserve(static_cast<size_t>(n_samples));

        if (!json && !csv) {
            std::cout << c.bold("== " + host + " ==");
            std::cout << c.dim("  (" + ep.to_string() + ")") << "\n";
        }

        for (int s = 0; s < n_samples; ++s) {
            if (interrupted()) break;
            QueryResult r = client.query(ep, cfg);
            r.server = ep;
            samples.push_back(r);

            if (r.success && r.time_valid) {
                off.add(r.offset);
                del.add(r.delay);
                last_good = r;
                have_good = true;
            } else {
                loss++;
            }

            if (csv) {
                std::cout << query_csv_row(host, r) << "\n";
            } else if (!json) {
                std::ostringstream ln;
                ln << "  [" << (s + 1) << "] ";
                if (r.success && r.time_valid) {
                    ln << "offset=" << colorize_offset(c, r.offset)
                       << "  delay=" << ms3(r.delay) << " ms"
                       << "  stratum=" << static_cast<int>(r.response.stratum);
                    if (r.auth_requested)
                        ln << "  auth=" << (r.auth_valid ? c.green("ok")
                                                         : c.red("bad"));
                } else if (r.kiss_of_death) {
                    ln << c.red("KoD " + r.kiss_code);
                } else {
                    ln << c.red("failed: ") << r.error;
                }
                std::cout << ln.str() << "\n";
            }

            if (s + 1 < n_samples) sleep_seconds(opt.interval);
        }

        if (json) {
            if (!first_host) std::cout << ",\n";
            first_host = false;
            std::cout << "  {\n";
            std::cout << "    \"host\": \"" << json_escape(host) << "\",\n";
            std::cout << "    \"address\": \"" << json_escape(ep.to_string())
                      << "\",\n";
            std::cout << "    \"loss\": " << loss << ",\n";
            std::cout << "    \"samples\": [\n";
            for (size_t k = 0; k < samples.size(); ++k) {
                std::cout << query_result_to_json(host, samples[k], 6);
                std::cout << (k + 1 < samples.size() ? ",\n" : "\n");
            }
            std::cout << "    ],\n";
            std::cout << "    \"statistics\": {\n";
            std::cout << stat_json("offset_ms", off.summary(), 6) << ",\n";
            std::cout << stat_json("delay_ms", del.summary(), 6) << "\n";
            std::cout << "    }\n";
            std::cout << "  }";
        } else if (!csv) {
            if (have_good) {
                const NtpPacket& p = last_good.response;
                std::cout << "  " << c.dim("stratum ")
                          << static_cast<int>(p.stratum) << c.dim(", refid ")
                          << p.refid_string() << c.dim(", leap ")
                          << leap_to_string(p.leap) << c.dim(", precision 2^")
                          << static_cast<int>(p.precision) << "\n";
                print_summary_line(std::cout, "offset", off.summary(), c);
                print_summary_line(std::cout, "delay ", del.summary(), c);
            }
            std::cout << "  " << c.dim("packet loss: ") << loss << "/"
                      << n_samples;
            if (loss == n_samples) {
                std::cout << "  " << c.red("(no response)");
                exit_code = 1;
            }
            std::cout << "\n\n";
            if (opt.verbose >= 1 && have_good)
                print_query_report(std::cout, host, last_good, c, opt.verbose);
        }
    }

    if (json) std::cout << "\n]\n";
    return exit_code;
}

}  // namespace ntptool
