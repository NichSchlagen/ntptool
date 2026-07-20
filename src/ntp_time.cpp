#include "ntptool/ntp_time.hpp"

#include <chrono>
#include <cmath>

#include "ntptool/util.hpp"

namespace ntptool {

NtpTime ntp_now() {
    using namespace std::chrono;
    // Use the system clock for wall time. std::chrono::system_clock measures
    // time since the UNIX epoch on all mainstream implementations; we convert
    // to a high-resolution seconds value and then into the NTP domain.
    auto now = system_clock::now().time_since_epoch();
    auto secs = duration_cast<seconds>(now);
    auto frac = now - secs;
    double frac_seconds =
        duration_cast<duration<double>>(frac).count();

    uint64_t ntp_secs = static_cast<uint64_t>(secs.count()) + kNtpUnixDeltaSeconds;
    uint32_t ntp_frac = static_cast<uint32_t>(frac_seconds * kTwoPow32);

    NtpTime t;
    t.raw = (ntp_secs << 32) | ntp_frac;
    return t;
}

double ntp_to_unix(NtpTime t) {
    // Era-0 interpretation: subtract the NTP/UNIX epoch delta.
    int64_t unix_sec =
        static_cast<int64_t>(t.seconds()) - static_cast<int64_t>(kNtpUnixDeltaSeconds);
    double frac = static_cast<double>(t.fraction()) / kTwoPow32;
    return static_cast<double>(unix_sec) + frac;
}

NtpTime unix_to_ntp(double unix_seconds) {
    double intpart = std::floor(unix_seconds);
    double frac = unix_seconds - intpart;
    uint64_t ntp_secs =
        static_cast<uint64_t>(static_cast<int64_t>(intpart) +
                              static_cast<int64_t>(kNtpUnixDeltaSeconds));
    uint32_t ntp_frac = static_cast<uint32_t>(frac * kTwoPow32);
    NtpTime t;
    t.raw = (ntp_secs << 32) | ntp_frac;
    return t;
}

double ntp_diff_seconds(NtpTime a, NtpTime b) {
    // Wrapping subtraction in the unsigned domain, then reinterpret as signed.
    uint64_t d = a.raw - b.raw;
    int64_t sd = static_cast<int64_t>(d);
    return static_cast<double>(sd) / kTwoPow32;
}

std::string ntp_to_iso8601(NtpTime t) {
    if (t.is_zero()) return "0 (unset)";
    return format_unix_utc(ntp_to_unix(t), true);
}

}  // namespace ntptool
