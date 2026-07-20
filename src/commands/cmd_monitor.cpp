#include <chrono>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sstream>
#include <thread>

#include "ntptool/commands.hpp"
#include "ntptool/output.hpp"
#include "ntptool/statistics.hpp"
#include "ntptool/util.hpp"

namespace ntptool {
namespace {

std::string now_hms() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[16];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tmv);
    return buf;
}

std::string ms3(double s) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.3f", s * 1e3);
    return b;
}

void sleep_seconds(double s) {
    // Sleep in small slices so Ctrl-C is honoured promptly.
    double remaining = s;
    while (remaining > 0 && !interrupted()) {
        double slice = remaining > 0.2 ? 0.2 : remaining;
        std::this_thread::sleep_for(std::chrono::duration<double>(slice));
        remaining -= slice;
    }
}

}  // namespace

int cmd_monitor(const Options& opt) {
    if (opt.hosts.empty()) {
        std::cerr << "monitor: no host given\n";
        return 2;
    }
    const std::string host = opt.hosts.front();
    const Colorizer& c = opt.color;

    std::string err;
    auto eps = resolve(host, opt.port, opt.family, err);
    if (eps.empty()) {
        std::cerr << "monitor: " << err << "\n";
        return 1;
    }
    Endpoint ep = eps.front();

    NtpClient client;
    QueryConfig cfg = make_query_config(opt);
    const bool csv = opt.format == OutputFormat::Csv;
    const bool json = opt.format == OutputFormat::Json;
    const bool infinite = (opt.count == 0);

    if (csv) {
        std::cout << "time,seq,success,stratum,offset_ms,delay_ms,rtt_ms,error\n";
    } else if (!json) {
        std::cout << c.bold("Monitoring ") << host << " (" << ep.to_string()
                  << ")  every " << opt.interval << "s";
        if (!infinite) std::cout << ", " << opt.count << " polls";
        std::cout << c.dim("   [Ctrl-C to stop]") << "\n\n";
    }

    Series off, del;
    int seq = 0;
    int loss = 0;

    while (!interrupted() && (infinite || seq < opt.count)) {
        QueryResult r = client.query(ep, cfg);
        ++seq;
        std::string ts = now_hms();

        if (r.success && r.time_valid) {
            off.add(r.offset);
            del.add(r.delay);
        } else {
            ++loss;
        }

        if (csv) {
            std::cout << ts << "," << seq << "," << (r.success ? 1 : 0) << ",";
            if (r.success && r.time_valid)
                std::cout << static_cast<int>(r.response.stratum) << ","
                          << ms3(r.offset) << "," << ms3(r.delay) << ","
                          << ms3(r.rtt) << ",";
            else
                std::cout << ",,,," ;
            std::cout << csv_escape(r.error) << "\n";
            std::cout.flush();
        } else if (json) {
            std::ostringstream js;
            js.setf(std::ios::fixed);
            js << "{\"time\":\"" << ts << "\",\"seq\":" << seq
               << ",\"success\":" << (r.success && r.time_valid ? "true" : "false");
            if (r.success && r.time_valid)
                js << ",\"stratum\":" << static_cast<int>(r.response.stratum)
                   << ",\"offset_ms\":" << r.offset * 1e3
                   << ",\"delay_ms\":" << r.delay * 1e3;
            if (!r.error.empty()) js << ",\"error\":\"" << json_escape(r.error) << "\"";
            js << "}";
            std::cout << js.str() << "\n";
            std::cout.flush();
        } else {
            std::ostringstream ln;
            ln << c.dim("[" + ts + "] ") << "#" << seq << "  ";
            if (r.success && r.time_valid) {
                StatSummary os = off.summary();
                ln << "offset=" << colorize_offset(c, r.offset)
                   << "  delay=" << ms3(r.delay) << " ms"
                   << "  str=" << static_cast<int>(r.response.stratum)
                   << c.dim("  [avg " + ms3(os.mean) + " jit " + ms3(os.jitter) +
                            " ms]");
            } else if (r.kiss_of_death) {
                ln << c.red("Kiss-o'-Death: " + r.kiss_code);
            } else {
                ln << c.red("no reply: ") << r.error;
            }
            std::cout << ln.str() << "\n";
            std::cout.flush();
        }

        if (infinite || seq < opt.count) sleep_seconds(opt.interval);
    }

    if (!csv && !json) {
        std::cout << "\n" << c.bold("Summary") << " after " << seq << " polls ("
                  << loss << " lost):\n";
        StatSummary os = off.summary();
        StatSummary ds = del.summary();
        if (os.n > 0) {
            std::cout << "  offset  min/avg/median/max = " << ms3(os.min) << " / "
                      << ms3(os.mean) << " / " << ms3(os.median) << " / "
                      << ms3(os.max) << " ms   stddev " << ms3(os.stddev)
                      << " jitter " << ms3(os.jitter) << "\n";
            std::cout << "  delay   min/avg/median/max = " << ms3(ds.min) << " / "
                      << ms3(ds.mean) << " / " << ms3(ds.median) << " / "
                      << ms3(ds.max) << " ms\n";
        } else {
            std::cout << "  " << c.red("no successful measurements") << "\n";
        }
    }

    return off.summary().n > 0 ? 0 : 1;
}

}  // namespace ntptool
