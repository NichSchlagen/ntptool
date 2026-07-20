#include "ntptool/ntp_packet.hpp"

#include <cstdio>

#include "ntptool/util.hpp"

namespace ntptool {

const char* leap_to_string(LeapIndicator li) {
    switch (li) {
        case LeapIndicator::NoWarning:      return "no-warning";
        case LeapIndicator::Add:            return "leap-add (+1s)";
        case LeapIndicator::Sub:            return "leap-sub (-1s)";
        case LeapIndicator::Unsynchronized: return "unsynchronized";
    }
    return "?";
}

const char* mode_to_string(NtpMode m) {
    switch (m) {
        case NtpMode::Reserved:   return "reserved";
        case NtpMode::SymActive:  return "symmetric-active";
        case NtpMode::SymPassive: return "symmetric-passive";
        case NtpMode::Client:     return "client";
        case NtpMode::Server:     return "server";
        case NtpMode::Broadcast:  return "broadcast";
        case NtpMode::Control:    return "control";
        case NtpMode::Private:    return "private";
    }
    return "?";
}

std::vector<uint8_t> NtpPacket::serialize() const {
    std::vector<uint8_t> b;
    b.reserve(48 + (has_mac ? 4 + mac.size() : 0));

    uint8_t li_vn_mode = static_cast<uint8_t>(
        (static_cast<uint8_t>(leap) << 6) |
        ((version & 0x07) << 3) |
        (static_cast<uint8_t>(mode) & 0x07));
    b.push_back(li_vn_mode);
    b.push_back(stratum);
    b.push_back(static_cast<uint8_t>(poll));
    b.push_back(static_cast<uint8_t>(precision));

    put_u32(b, root_delay);
    put_u32(b, root_dispersion);
    put_u32(b, reference_id);
    put_u64(b, reference_ts.raw);
    put_u64(b, originate_ts.raw);
    put_u64(b, receive_ts.raw);
    put_u64(b, transmit_ts.raw);

    if (has_mac) {
        put_u32(b, key_id);
        b.insert(b.end(), mac.begin(), mac.end());
    }
    return b;
}

bool NtpPacket::parse(const uint8_t* data, size_t len, NtpPacket& out) {
    if (len < 48) return false;

    uint8_t li_vn_mode = data[0];
    out.leap = static_cast<LeapIndicator>((li_vn_mode >> 6) & 0x03);
    out.version = static_cast<uint8_t>((li_vn_mode >> 3) & 0x07);
    out.mode = static_cast<NtpMode>(li_vn_mode & 0x07);
    out.stratum = data[1];
    out.poll = static_cast<int8_t>(data[2]);
    out.precision = static_cast<int8_t>(data[3]);

    out.root_delay = get_u32(data + 4);
    out.root_dispersion = get_u32(data + 8);
    out.reference_id = get_u32(data + 12);
    out.reference_ts.raw = get_u64(data + 16);
    out.originate_ts.raw = get_u64(data + 24);
    out.receive_ts.raw = get_u64(data + 32);
    out.transmit_ts.raw = get_u64(data + 40);

    // Optional authenticator: key id (4 bytes) + MAC (16 or 20 bytes).
    if (len >= 48 + 4 + 16) {
        out.has_mac = true;
        out.key_id = get_u32(data + 48);
        out.mac.assign(data + 52, data + len);
    } else {
        out.has_mac = false;
        out.key_id = 0;
        out.mac.clear();
    }
    return true;
}

std::string NtpPacket::refid_ascii() const {
    char c[4] = {
        static_cast<char>((reference_id >> 24) & 0xFF),
        static_cast<char>((reference_id >> 16) & 0xFF),
        static_cast<char>((reference_id >> 8) & 0xFF),
        static_cast<char>(reference_id & 0xFF),
    };
    std::string s;
    for (char ch : c) {
        if (ch == '\0') break;
        s += (ch >= 0x20 && ch < 0x7F) ? ch : '.';
    }
    return s;
}

std::string NtpPacket::refid_string() const {
    if (refid_is_ascii()) {
        std::string a = refid_ascii();
        if (a.empty()) return "(none)";
        return a;
    }
    // Stratum >= 2: IPv4 dotted quad (NTPv4 over IPv4). For IPv6 upstreams this
    // field holds the low 32 bits of an MD5 hash and is not a real address, but
    // there is no way to tell them apart from the packet alone.
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (reference_id >> 24) & 0xFF,
                  (reference_id >> 16) & 0xFF,
                  (reference_id >> 8) & 0xFF,
                  reference_id & 0xFF);
    return buf;
}

}  // namespace ntptool
