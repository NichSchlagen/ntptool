#include "ntptool/ntp_control.hpp"

#include <cstring>
#include <random>

#include "ntptool/ntp_packet.hpp"
#include "ntptool/util.hpp"

namespace ntptool {
namespace {

uint16_t random_sequence() {
    static std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(1, 0xFFFF);
    return static_cast<uint16_t>(dist(rng));
}

}  // namespace

ControlResponse NtpControlClient::request(const Endpoint& server, uint8_t opcode,
                                          uint16_t assoc_id,
                                          const std::string& payload,
                                          const ControlConfig& cfg) {
    ControlResponse out;

    // ---- Build request header (12 bytes) ----------------------------------
    std::vector<uint8_t> req;
    uint8_t li_vn_mode = static_cast<uint8_t>(
        ((cfg.version & 0x07) << 3) | (static_cast<uint8_t>(NtpMode::Control) & 0x07));
    req.push_back(li_vn_mode);
    req.push_back(static_cast<uint8_t>(opcode & 0x1F));  // R/E/M = 0 for request
    uint16_t seq = random_sequence();
    put_u16(req, seq);
    put_u16(req, 0);                                        // status
    put_u16(req, assoc_id);                                 // association id
    put_u16(req, 0);                                        // offset
    put_u16(req, static_cast<uint16_t>(payload.size()));    // count
    req.insert(req.end(), payload.begin(), payload.end());
    while (req.size() % 4 != 0) req.push_back(0);           // pad to 4 bytes

    // ---- Socket ------------------------------------------------------------
    UdpSocket sock;
    std::string err;
    sock.set_recv_timeout(cfg.timeout);
    if (!sock.open(server.family(), err)) {
        out.error = err;
        return out;
    }
    if (!sock.send_to(server, req.data(), req.size(), err)) {
        out.error = err;
        return out;
    }

    // ---- Receive and reassemble fragments ---------------------------------
    // Payload is placed by (offset) so fragments can arrive out of order.
    std::vector<uint8_t> assembled;
    bool got_any = false;

    for (int frag = 0; frag < cfg.max_fragments; ++frag) {
        std::vector<uint8_t> buf;
        Endpoint from;
        RecvStatus st = sock.recv_from(buf, from, err);
        if (st == RecvStatus::Timeout) {
            if (!got_any) out.error = "no mode-6 response (timeout; likely restricted)";
            break;
        }
        if (st == RecvStatus::Error) {
            if (!got_any) out.error = err;
            break;
        }
        if (buf.size() < 12) continue;

        NtpMode m = static_cast<NtpMode>(buf[0] & 0x07);
        if (m != NtpMode::Control) continue;
        uint16_t rseq = get_u16(buf.data() + 2);
        if (rseq != seq) continue;  // not our transaction

        bool response_bit = (buf[1] & 0x80) != 0;
        bool error_bit = (buf[1] & 0x40) != 0;
        bool more_bit = (buf[1] & 0x20) != 0;
        uint8_t rop = buf[1] & 0x1F;
        uint16_t status = get_u16(buf.data() + 4);
        uint16_t rassoc = get_u16(buf.data() + 6);
        uint16_t offset = get_u16(buf.data() + 8);
        uint16_t count = get_u16(buf.data() + 10);

        if (!response_bit) continue;  // ignore echoes of our own request

        out.response_bit = true;
        out.error_bit = error_bit;
        out.opcode = rop;
        out.status = status;
        out.assoc_id = rassoc;
        out.fragments++;
        got_any = true;

        if (error_bit) {
            out.error = "server returned control error (status 0x" +
                        [&] {
                            char b[8];
                            std::snprintf(b, sizeof(b), "%04x", status);
                            return std::string(b);
                        }() +
                        ")";
            out.success = false;
            return out;
        }

        size_t avail = buf.size() - 12;
        size_t n = std::min<size_t>(count, avail);
        if (static_cast<size_t>(offset) + n > assembled.size())
            assembled.resize(static_cast<size_t>(offset) + n);
        std::memcpy(assembled.data() + offset, buf.data() + 12, n);

        if (!more_bit) break;  // last fragment
    }

    out.data = std::move(assembled);
    out.success = got_any;
    if (got_any) out.error.clear();
    return out;
}

ControlResponse NtpControlClient::read_variables(const Endpoint& server,
                                                 uint16_t assoc_id,
                                                 const std::string& vars,
                                                 const ControlConfig& cfg) {
    return request(server, kCtlOpReadVar, assoc_id, vars, cfg);
}

ControlResponse NtpControlClient::read_associations(const Endpoint& server,
                                                    const ControlConfig& cfg) {
    return request(server, kCtlOpReadStat, 0, "", cfg);
}

std::vector<std::pair<std::string, std::string>> parse_ntp_vars(
    const std::string& text) {
    std::vector<std::pair<std::string, std::string>> out;

    // Split on commas that are not inside double quotes.
    std::vector<std::string> tokens;
    std::string cur;
    bool in_quotes = false;
    for (char c : text) {
        if (c == '"') {
            in_quotes = !in_quotes;
            cur += c;
        } else if (c == ',' && !in_quotes) {
            tokens.push_back(cur);
            cur.clear();
        } else if (c == '\r' || c == '\n') {
            // fold line breaks into spaces
            cur += ' ';
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) tokens.push_back(cur);

    for (auto& tok : tokens) {
        std::string t = trim(tok);
        if (t.empty()) continue;
        size_t eq = t.find('=');
        std::string key, val;
        if (eq == std::string::npos) {
            key = t;  // bare flag
        } else {
            key = trim(t.substr(0, eq));
            val = trim(t.substr(eq + 1));
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size() - 2);
        }
        if (!key.empty()) out.emplace_back(key, val);
    }
    return out;
}

std::vector<AssocEntry> parse_assoc_list(const std::vector<uint8_t>& data) {
    std::vector<AssocEntry> out;
    for (size_t i = 0; i + 4 <= data.size(); i += 4) {
        AssocEntry e;
        e.assoc_id = get_u16(data.data() + i);
        e.peer_status = get_u16(data.data() + i + 2);
        if (e.assoc_id == 0) continue;
        out.push_back(e);
    }
    return out;
}

std::string peer_status_string(uint16_t status) {
    // Peer status word: high byte holds select/flags, low nibble the event code.
    // Selection field: bits 8..10 of the 16-bit word.
    uint8_t sel = static_cast<uint8_t>((status >> 8) & 0x07);
    const char* sel_names[] = {"reject",    "falsetick", "excess",  "outlier",
                               "candidate", "backup",    "sys.peer", "pps.peer"};
    std::string s = sel_names[sel];

    uint8_t flags = static_cast<uint8_t>((status >> 8) & 0xF8);
    if (flags & 0x80) s += ",config";
    if (flags & 0x40) s += ",authenb";
    if (flags & 0x20) s += ",authok";
    if (flags & 0x10) s += ",reach";
    return s;
}

}  // namespace ntptool
