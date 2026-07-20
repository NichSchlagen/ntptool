#include <cstdio>
#include <iostream>
#include <sstream>

#include "ntptool/commands.hpp"
#include "ntptool/ntp_control.hpp"
#include "ntptool/output.hpp"
#include "ntptool/util.hpp"

namespace ntptool {

int cmd_control(const Options& opt) {
    if (opt.hosts.empty()) {
        std::cerr << "control: no host given\n";
        return 2;
    }
    const std::string host = opt.hosts.front();
    const Colorizer& c = opt.color;

    std::string err;
    auto eps = resolve(host, opt.port, opt.family, err);
    if (eps.empty()) {
        std::cerr << "control: " << err << "\n";
        return 1;
    }
    Endpoint ep = eps.front();

    NtpControlClient ctl;
    ControlConfig cfg;
    cfg.version = 2;
    cfg.timeout = opt.timeout;

    // ---- Association list --------------------------------------------------
    if (opt.list_assoc) {
        ControlResponse resp = ctl.read_associations(ep, cfg);
        if (!resp.success) {
            std::cerr << "control: " << resp.error << "\n";
            return 1;
        }
        auto assocs = parse_assoc_list(resp.data);
        if (opt.format == OutputFormat::Json) {
            std::cout << "{\n  \"host\": \"" << json_escape(host)
                      << "\",\n  \"associations\": [\n";
            for (size_t i = 0; i < assocs.size(); ++i) {
                char b[16];
                std::snprintf(b, sizeof(b), "0x%04x", assocs[i].peer_status);
                std::cout << "    {\"assoc_id\": " << assocs[i].assoc_id
                          << ", \"status\": \"" << b << "\", \"condition\": \""
                          << json_escape(peer_status_string(assocs[i].peer_status))
                          << "\"}" << (i + 1 < assocs.size() ? ",\n" : "\n");
            }
            std::cout << "  ]\n}\n";
            return 0;
        }
        std::cout << c.bold("Associations on " + host) << " ("
                  << assocs.size() << "):\n";
        char hdr[128];
        std::snprintf(hdr, sizeof(hdr), "  %-8s %-8s %s", "ASSOC", "STATUS",
                      "CONDITION");
        std::cout << c.dim(hdr) << "\n";
        for (const auto& a : assocs) {
            char line[160];
            std::snprintf(line, sizeof(line), "  %-8u 0x%04x  %s", a.assoc_id,
                          a.peer_status, peer_status_string(a.peer_status).c_str());
            std::cout << line << "\n";
        }
        if (assocs.empty())
            std::cout << c.dim("  (no associations reported)") << "\n";
        return 0;
    }

    // ---- Read variables ----------------------------------------------------
    uint16_t assoc = static_cast<uint16_t>(opt.assoc_id);
    ControlResponse resp =
        ctl.read_variables(ep, assoc, opt.control_vars, cfg);
    if (!resp.success) {
        std::cerr << "control: " << resp.error << "\n";
        return 1;
    }

    auto vars = parse_ntp_vars(resp.data_text());

    if (opt.format == OutputFormat::Json) {
        std::cout << "{\n  \"host\": \"" << json_escape(host)
                  << "\",\n  \"assoc_id\": " << assoc << ",\n  \"variables\": {\n";
        for (size_t i = 0; i < vars.size(); ++i)
            std::cout << "    \"" << json_escape(vars[i].first) << "\": \""
                      << json_escape(vars[i].second) << "\""
                      << (i + 1 < vars.size() ? ",\n" : "\n");
        std::cout << "  }\n}\n";
        return 0;
    }
    if (opt.format == OutputFormat::Csv) {
        std::cout << "name,value\n";
        for (const auto& kv : vars)
            std::cout << csv_escape(kv.first) << "," << csv_escape(kv.second)
                      << "\n";
        return 0;
    }

    std::cout << c.bold("Mode-6 variables from " + host)
              << (assoc ? "  (assoc " + std::to_string(assoc) + ")" : "  (system)")
              << ":\n";
    if (opt.verbose >= 1)
        std::cout << c.dim("  fragments: " + std::to_string(resp.fragments) +
                           ", bytes: " + std::to_string(resp.data.size()))
                  << "\n";
    for (const auto& kv : vars) {
        std::cout << "  " << c.cyan(kv.first);
        if (!kv.second.empty()) std::cout << " = " << kv.second;
        std::cout << "\n";
    }
    if (vars.empty())
        std::cout << c.dim("  (server returned no variables)") << "\n";
    return 0;
}

}  // namespace ntptool
