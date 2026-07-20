#include "ntptool/output.hpp"

#include <cmath>
#include <cstdio>
#include <iomanip>
#include <sstream>

#include "ntptool/util.hpp"

namespace ntptool {

std::string Colorizer::paint(const char* code, const std::string& s) const {
    if (!enabled) return s;
    return std::string("\033[") + code + "m" + s + "\033[0m";
}

const char* offset_quality(double offset_seconds) {
    double a = std::fabs(offset_seconds);
    if (a < 0.001) return "excellent";
    if (a < 0.010) return "good";
    if (a < 0.100) return "fair";
    if (a < 1.000) return "poor";
    return "bad";
}

std::string colorize_offset(const Colorizer& c, double offset_seconds) {
    std::string txt = format_ms_signed(offset_seconds);
    double a = std::fabs(offset_seconds);
    if (a < 0.010) return c.green(txt);
    if (a < 0.100) return c.yellow(txt);
    return c.red(txt);
}

namespace {
std::string pad(const std::string& s, size_t w) {
    if (s.size() >= w) return s;
    return s + std::string(w - s.size(), ' ');
}
}  // namespace

void print_query_report(std::ostream& os, const std::string& host,
                        const QueryResult& r, const Colorizer& c, int verbose) {
    const NtpPacket& p = r.response;

    os << c.bold("Server") << "        " << host;
    if (r.server.valid()) os << "  (" << r.server.to_string() << ")";
    os << "\n";

    if (!r.success) {
        os << c.red("  error: ") << r.error << "\n";
        return;
    }

    if (r.kiss_of_death) {
        os << pad("  Kiss-o'-Death", 14) << c.red(r.kiss_code)
           << "  — server refuses service (rate limit / restriction)\n";
    }

    // Response summary line.
    {
        std::ostringstream ss;
        ss << mode_to_string(p.mode) << ", NTPv" << static_cast<int>(p.version)
           << ", stratum " << static_cast<int>(p.stratum);
        os << pad("  Response", 14) << ss.str() << "\n";
    }

    os << pad("  Reference", 14) << p.refid_string();
    if (!p.reference_ts.is_zero())
        os << "  (last sync " << ntp_to_iso8601(p.reference_ts) << ")";
    os << "\n";

    // Leap indicator (colourised on alarm).
    {
        std::string ls = leap_to_string(p.leap);
        if (p.leap == LeapIndicator::Unsynchronized) ls = c.red(ls);
        else if (p.leap != LeapIndicator::NoWarning) ls = c.yellow(ls);
        os << pad("  Leap", 14) << ls << "\n";
    }

    // Precision.
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "2^%d (%s)", p.precision,
                      format_seconds_adaptive(r.precision_seconds).c_str());
        os << pad("  Precision", 14) << buf << "\n";
    }

    // Root delay / dispersion / distance.
    os << pad("  Root", 14) << "delay "
       << format_seconds_adaptive(r.root_delay) << ", dispersion "
       << format_seconds_adaptive(r.root_dispersion) << ", distance "
       << format_seconds_adaptive(r.root_distance) << "\n";

    // Poll.
    {
        double poll_s = std::pow(2.0, static_cast<double>(p.poll));
        char buf[64];
        std::snprintf(buf, sizeof(buf), "2^%d (%.0f s)", p.poll, poll_s);
        os << pad("  Poll", 14) << buf << "\n";
    }

    if (r.time_valid) {
        os << pad("  Offset", 14) << colorize_offset(c, r.offset) << "   ["
           << offset_quality(r.offset) << "]\n";
        os << pad("  Delay", 14) << format_seconds_adaptive(r.delay) << "\n";
        os << pad("  RTT", 14) << format_seconds_adaptive(r.rtt) << "\n";
    }

    if (r.auth_requested) {
        std::string a;
        if (!r.auth_present) a = c.yellow("no MAC in reply");
        else if (r.auth_valid) a = c.green("valid");
        else a = c.red("INVALID");
        os << pad("  Auth", 14) << a << "\n";
    }

    if (verbose >= 1) {
        os << pad("  T1 xmit", 14) << ntp_to_iso8601(r.t1) << "\n";
        os << pad("  T2 recv", 14) << ntp_to_iso8601(r.t2) << "\n";
        os << pad("  T3 xmit", 14) << ntp_to_iso8601(r.t3) << "\n";
        os << pad("  T4 dest", 14) << ntp_to_iso8601(r.t4) << "\n";
    }

    if (verbose >= 2) {
        if (!r.raw_request.empty()) {
            os << c.dim("  request bytes:\n")
               << hexdump(r.raw_request.data(), r.raw_request.size());
        }
        if (!r.raw_response.empty()) {
            os << c.dim("  response bytes:\n")
               << hexdump(r.raw_response.data(), r.raw_response.size());
        }
    }
}

std::string query_result_to_json(const std::string& host, const QueryResult& r,
                                 int indent) {
    std::string in(static_cast<size_t>(indent), ' ');
    std::string in2 = in + "  ";
    std::ostringstream os;
    // Use general notation with generous precision so both millisecond-scale
    // values and tiny quantities (e.g. precision ~2^-25 s) render exactly.
    os << std::setprecision(10);

    os << in << "{\n";
    os << in2 << "\"host\": \"" << json_escape(host) << "\",\n";
    os << in2 << "\"address\": \""
       << json_escape(r.server.valid() ? r.server.to_string() : "") << "\",\n";
    os << in2 << "\"success\": " << (r.success ? "true" : "false") << ",\n";
    os << in2 << "\"time_valid\": " << (r.time_valid ? "true" : "false") << ",\n";
    if (!r.error.empty())
        os << in2 << "\"error\": \"" << json_escape(r.error) << "\",\n";

    if (r.success) {
        const NtpPacket& p = r.response;
        os << in2 << "\"mode\": \"" << mode_to_string(p.mode) << "\",\n";
        os << in2 << "\"version\": " << static_cast<int>(p.version) << ",\n";
        os << in2 << "\"stratum\": " << static_cast<int>(p.stratum) << ",\n";
        os << in2 << "\"leap\": \"" << leap_to_string(p.leap) << "\",\n";
        os << in2 << "\"refid\": \"" << json_escape(p.refid_string()) << "\",\n";
        os << in2 << "\"precision_seconds\": " << r.precision_seconds << ",\n";
        os << in2 << "\"root_delay_ms\": " << r.root_delay * 1e3 << ",\n";
        os << in2 << "\"root_dispersion_ms\": " << r.root_dispersion * 1e3 << ",\n";
        os << in2 << "\"root_distance_ms\": " << r.root_distance * 1e3 << ",\n";
        os << in2 << "\"kiss_of_death\": " << (r.kiss_of_death ? "true" : "false")
           << ",\n";
        if (r.kiss_of_death)
            os << in2 << "\"kiss_code\": \"" << json_escape(r.kiss_code)
               << "\",\n";
        if (r.time_valid) {
            os << in2 << "\"offset_ms\": " << r.offset * 1e3 << ",\n";
            os << in2 << "\"delay_ms\": " << r.delay * 1e3 << ",\n";
            os << in2 << "\"rtt_ms\": " << r.rtt * 1e3 << ",\n";
        }
        if (r.auth_requested) {
            os << in2 << "\"auth_present\": " << (r.auth_present ? "true" : "false")
               << ",\n";
            os << in2 << "\"auth_valid\": " << (r.auth_valid ? "true" : "false")
               << ",\n";
        }
    }
    os << in2 << "\"quality\": \""
       << (r.time_valid ? offset_quality(r.offset) : "n/a") << "\"\n";
    os << in << "}";
    return os.str();
}

std::string query_csv_header() {
    return "host,address,success,stratum,leap,refid,offset_ms,delay_ms,rtt_ms,"
           "root_delay_ms,root_dispersion_ms,precision_s,quality,error";
}

std::string query_csv_row(const std::string& host, const QueryResult& r) {
    std::ostringstream os;
    os.setf(std::ios::fixed);
    os << csv_escape(host) << ","
       << csv_escape(r.server.valid() ? r.server.to_string() : "") << ","
       << (r.success ? "1" : "0") << ",";
    if (r.success) {
        os << static_cast<int>(r.response.stratum) << ","
           << leap_to_string(r.response.leap) << ","
           << csv_escape(r.response.refid_string()) << ",";
        if (r.time_valid) {
            os << r.offset * 1e3 << "," << r.delay * 1e3 << "," << r.rtt * 1e3
               << ",";
        } else {
            os << ",,,";
        }
        os << r.root_delay * 1e3 << "," << r.root_dispersion * 1e3 << ","
           << r.precision_seconds << ","
           << (r.time_valid ? offset_quality(r.offset) : "n/a") << ",";
    } else {
        os << ",,,,,,,,,";
    }
    os << csv_escape(r.error);
    return os.str();
}

}  // namespace ntptool
