#include "ntptool/util.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <sstream>

namespace ntptool {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream iss(s);
    while (std::getline(iss, cur, delim)) out.push_back(cur);
    return out;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c & 0xFF);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string csv_escape(const std::string& s) {
    bool need = s.find_first_of(",\"\n\r") != std::string::npos;
    if (!need) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string format_seconds_adaptive(double seconds) {
    double a = std::fabs(seconds);
    char buf[64];
    const char* unit;
    double val;
    if (a < 1e-6) {
        val = seconds * 1e9;
        unit = "ns";
    } else if (a < 1e-3) {
        val = seconds * 1e6;
        unit = "us";
    } else if (a < 1.0) {
        val = seconds * 1e3;
        unit = "ms";
    } else {
        val = seconds;
        unit = "s";
    }
    std::snprintf(buf, sizeof(buf), "%.3f %s", val, unit);
    return buf;
}

std::string format_ms_signed(double seconds) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%+.3f ms", seconds * 1e3);
    return buf;
}

std::string format_unix_utc(double unix_seconds, bool with_fraction) {
    // Split into integer seconds and fractional part.
    double intpart = std::floor(unix_seconds);
    double frac = unix_seconds - intpart;
    std::time_t t = static_cast<std::time_t>(intpart);

    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif

    char base[32];
    std::strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tmv);
    std::string out(base);
    if (with_fraction) {
        char fbuf[16];
        std::snprintf(fbuf, sizeof(fbuf), ".%03d", static_cast<int>(frac * 1000.0 + 0.5));
        out += fbuf;
    }
    out += "Z";
    return out;
}

std::string hexdump(const uint8_t* data, size_t len) {
    std::string out;
    char line[128];
    for (size_t off = 0; off < len; off += 16) {
        std::snprintf(line, sizeof(line), "%04zx  ", off);
        out += line;

        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < len) {
                uint8_t b = data[off + i];
                std::snprintf(line, sizeof(line), "%02x ", b);
                out += line;
                ascii += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
            } else {
                out += "   ";
            }
            if (i == 7) out += " ";
        }
        out += " |";
        out += ascii;
        out += "|\n";
    }
    return out;
}

}  // namespace ntptool
