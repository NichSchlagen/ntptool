#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "ntptool/commands.hpp"
#include "ntptool/md5.hpp"
#include "ntptool/ntp_time.hpp"
#include "ntptool/sha1.hpp"

namespace ntptool {
namespace {

int g_pass = 0;
int g_fail = 0;

void check(const std::string& name, bool ok, const Colorizer& c) {
    if (ok) {
        ++g_pass;
        std::cout << "  " << c.green("PASS") << "  " << name << "\n";
    } else {
        ++g_fail;
        std::cout << "  " << c.red("FAIL") << "  " << name << "\n";
    }
}

}  // namespace

int cmd_selftest(const Options& opt) {
    const Colorizer& c = opt.color;
    g_pass = g_fail = 0;

    std::cout << "Running internal self-tests...\n\n";

    // --- MD5 known-answer tests (RFC 1321) ---------------------------------
    {
        std::string e = md5_hex(reinterpret_cast<const uint8_t*>(""), 0);
        check("MD5(\"\") = d41d8cd98f00b204e9800998ecf8427e",
              e == "d41d8cd98f00b204e9800998ecf8427e", c);

        std::string s = "abc";
        std::string a = md5_hex(reinterpret_cast<const uint8_t*>(s.data()),
                                s.size());
        check("MD5(\"abc\") = 900150983cd24fb0d6963f7d28e17f72",
              a == "900150983cd24fb0d6963f7d28e17f72", c);

        std::string s2 =
            "The quick brown fox jumps over the lazy dog";
        std::string a2 = md5_hex(reinterpret_cast<const uint8_t*>(s2.data()),
                                 s2.size());
        check("MD5(fox) = 9e107d9d372bb6826bd81d3542a419d6",
              a2 == "9e107d9d372bb6826bd81d3542a419d6", c);
    }

    // --- SHA-1 known-answer tests (RFC 3174) -------------------------------
    {
        std::string e = sha1_hex(reinterpret_cast<const uint8_t*>(""), 0);
        check("SHA1(\"\") = da39a3ee5e6b4b0d3255bfef95601890afd80709",
              e == "da39a3ee5e6b4b0d3255bfef95601890afd80709", c);

        std::string s = "abc";
        std::string a = sha1_hex(reinterpret_cast<const uint8_t*>(s.data()),
                                 s.size());
        check("SHA1(\"abc\") = a9993e364706816aba3e25717850c26c9cd0d89d",
              a == "a9993e364706816aba3e25717850c26c9cd0d89d", c);
    }

    // --- NTP timestamp round-trips -----------------------------------------
    {
        // The UNIX epoch corresponds to NTP seconds 2208988800.
        NtpTime t = unix_to_ntp(0.0);
        check("unix_to_ntp(0) seconds == 2208988800",
              t.seconds() == 2208988800u, c);

        double back = ntp_to_unix(unix_to_ntp(1721470000.0));
        check("ntp<->unix round trip within 1us",
              std::fabs(back - 1721470000.0) < 1e-6, c);

        // Difference across values must be exact for whole seconds.
        NtpTime a = unix_to_ntp(1000.0);
        NtpTime b = unix_to_ntp(1000.5);
        double d = ntp_diff_seconds(b, a);
        check("ntp_diff_seconds(+0.5s) ~= 0.5", std::fabs(d - 0.5) < 1e-6, c);
    }

    // --- NTP MAC sanity (MD5 over key||header) -----------------------------
    {
        std::vector<uint8_t> key = {'s', 'e', 'c', 'r', 'e', 't'};
        std::vector<uint8_t> header(48, 0);
        auto mac = compute_ntp_mac(AuthType::MD5, key, header.data(),
                                   header.size());
        // Recompute directly and compare.
        std::vector<uint8_t> buf(key);
        buf.insert(buf.end(), header.begin(), header.end());
        auto direct = md5(buf.data(), buf.size());
        bool eq = mac.size() == 16 &&
                  std::equal(mac.begin(), mac.end(), direct.begin());
        check("NTP MD5 MAC matches H(key||header)", eq, c);
    }

    std::cout << "\n" << (g_fail == 0 ? c.green("All tests passed") : c.red("FAILURES"))
              << ": " << g_pass << " passed, " << g_fail << " failed.\n";
    return g_fail == 0 ? 0 : 1;
}

}  // namespace ntptool
