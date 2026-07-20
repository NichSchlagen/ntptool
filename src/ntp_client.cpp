#include "ntptool/ntp_client.hpp"

#include <cmath>
#include <cstring>

#include "ntptool/md5.hpp"
#include "ntptool/sha1.hpp"
#include "ntptool/util.hpp"

namespace ntptool {

const char* auth_type_name(AuthType t) {
    switch (t) {
        case AuthType::None: return "none";
        case AuthType::MD5:  return "MD5";
        case AuthType::SHA1: return "SHA1";
    }
    return "?";
}

std::vector<uint8_t> compute_ntp_mac(AuthType type,
                                     const std::vector<uint8_t>& key,
                                     const uint8_t* header, size_t header_len) {
    // NTP classic keyed digest: H(key || packet-header).
    std::vector<uint8_t> buf;
    buf.reserve(key.size() + header_len);
    buf.insert(buf.end(), key.begin(), key.end());
    buf.insert(buf.end(), header, header + header_len);

    std::vector<uint8_t> out;
    if (type == AuthType::MD5) {
        auto d = md5(buf.data(), buf.size());
        out.assign(d.begin(), d.end());
    } else if (type == AuthType::SHA1) {
        auto d = sha1(buf.data(), buf.size());
        out.assign(d.begin(), d.end());
    }
    return out;
}

QueryResult NtpClient::query(const Endpoint& server, const QueryConfig& cfg) {
    QueryResult r;
    r.server = server;
    r.auth_requested = (cfg.auth.type != AuthType::None);

    // ---- Build the request -------------------------------------------------
    NtpPacket req;
    req.leap = LeapIndicator::Unsynchronized;  // clients advertise "unsynced"
    req.version = cfg.version;
    req.mode = NtpMode::Client;
    req.stratum = 0;
    req.poll = 6;
    req.precision = -20;
    NtpTime xmit = ntp_now();
    req.transmit_ts = xmit;  // this becomes T1 and the anti-spoof cookie

    std::vector<uint8_t> wire = req.serialize();  // 48 bytes
    if (cfg.auth.type != AuthType::None) {
        auto mac = compute_ntp_mac(cfg.auth.type, cfg.auth.key, wire.data(),
                                   wire.size());
        put_u32(wire, cfg.auth.key_id);
        wire.insert(wire.end(), mac.begin(), mac.end());
    }
    if (cfg.capture_raw) r.raw_request = wire;

    // ---- Socket ------------------------------------------------------------
    UdpSocket sock;
    std::string err;
    sock.set_recv_timeout(cfg.timeout);
    if (!sock.open(server.family(), err)) {
        r.error = err;
        return r;
    }

    int attempts = cfg.retries + 1;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (!sock.send_to(server, wire.data(), wire.size(), err)) {
            r.error = err;
            return r;
        }

        std::vector<uint8_t> buf;
        Endpoint from;
        RecvStatus st = sock.recv_from(buf, from, err);
        if (st == RecvStatus::Timeout) {
            r.error = "timeout after " + std::to_string(cfg.timeout.count()) + " ms";
            continue;  // retry
        }
        if (st == RecvStatus::Error) {
            r.error = err;
            return r;
        }

        NtpTime t4 = ntp_now();  // capture destination timestamp immediately

        NtpPacket resp;
        if (!NtpPacket::parse(buf.data(), buf.size(), resp)) {
            r.error = "short/invalid response (" + std::to_string(buf.size()) +
                      " bytes)";
            continue;
        }

        if (cfg.capture_raw) r.raw_response = buf;
        r.response = resp;
        r.stratum = resp.stratum;
        r.leap = resp.leap;
        r.refid = resp.refid_string();
        r.root_delay = resp.root_delay_seconds();
        r.root_dispersion = resp.root_dispersion_seconds();
        r.root_distance = r.root_delay / 2.0 + r.root_dispersion;
        r.precision_seconds = std::pow(2.0, static_cast<double>(resp.precision));

        // ---- Validate ------------------------------------------------------
        if (resp.mode != NtpMode::Server && resp.mode != NtpMode::SymPassive) {
            r.error = std::string("unexpected mode in reply: ") +
                      mode_to_string(resp.mode);
            r.success = true;  // we got *a* reply, just not a usable one
            return r;
        }

        // Anti-spoofing: the server echoes our transmit timestamp as originate.
        if (resp.originate_ts.raw != xmit.raw) {
            r.error = "bogus reply: originate timestamp does not match request";
            r.success = true;
            return r;
        }

        // Kiss-o'-Death (stratum 0).
        if (resp.is_kiss_of_death()) {
            r.kiss_of_death = true;
            r.kiss_code = resp.refid_ascii();
            r.success = true;
            r.time_valid = false;
            r.error = "Kiss-o'-Death: " + r.kiss_code;
            r.t1 = xmit;
            r.t4 = t4;
            return r;
        }

        if (resp.transmit_ts.is_zero()) {
            r.error = "server transmit timestamp is zero (server not synced?)";
            r.success = true;
            return r;
        }

        // ---- Compute offset / delay ---------------------------------------
        r.t1 = xmit;
        r.t2 = resp.receive_ts;
        r.t3 = resp.transmit_ts;
        r.t4 = t4;

        double a = ntp_diff_seconds(r.t2, r.t1);  // T2 - T1
        double b = ntp_diff_seconds(r.t3, r.t4);  // T3 - T4
        r.offset = (a + b) / 2.0;
        r.delay = ntp_diff_seconds(r.t4, r.t1) - ntp_diff_seconds(r.t3, r.t2);
        if (r.delay < 0) r.delay = 0.0;  // clamp negative delay (clock jitter)
        r.rtt = ntp_diff_seconds(r.t4, r.t1);

        // ---- Authentication verification ----------------------------------
        if (r.auth_requested) {
            r.auth_present = resp.has_mac;
            if (resp.has_mac && buf.size() >= 48 &&
                resp.key_id == cfg.auth.key_id) {
                auto expect = compute_ntp_mac(cfg.auth.type, cfg.auth.key,
                                              buf.data(), 48);
                r.auth_valid = (expect.size() == resp.mac.size()) &&
                               std::equal(expect.begin(), expect.end(),
                                          resp.mac.begin());
            }
        }

        r.success = true;
        r.time_valid = true;
        r.error.clear();
        return r;
    }

    // All attempts exhausted (error already set to last timeout message).
    return r;
}

QueryResult NtpClient::query_host(const std::string& host, uint16_t port,
                                  IpFamily family, const QueryConfig& cfg) {
    QueryResult r;
    std::string err;
    auto eps = resolve(host, port, family, err);
    if (eps.empty()) {
        r.error = err;
        return r;
    }
    // Query the first address; on hard socket failure try the next.
    for (const auto& ep : eps) {
        r = query(ep, cfg);
        if (r.success || !r.error.empty()) return r;
    }
    return r;
}

}  // namespace ntptool
