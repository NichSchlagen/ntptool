#include <atomic>
#include <csignal>
#include <cstdio>
#include <iostream>

#include "ntptool/cli.hpp"
#include "ntptool/commands.hpp"
#include "ntptool/platform.hpp"

namespace ntptool {
namespace {
std::atomic<bool> g_interrupted{false};

void on_signal(int) { g_interrupted.store(true); }
}  // namespace

bool interrupted() { return g_interrupted.load(); }

void install_signal_handler() {
    std::signal(SIGINT, on_signal);
#if defined(SIGTERM)
    std::signal(SIGTERM, on_signal);
#endif
}

namespace {

int dispatch(const Options& opt) {
    switch (opt.command) {
        case Command::Query:    return cmd_query(opt);
        case Command::Monitor:  return cmd_monitor(opt);
        case Command::Compare:  return cmd_compare(opt);
        case Command::Scan:     return cmd_scan(opt);
        case Command::Control:  return cmd_control(opt);
        case Command::Security: return cmd_security(opt);
        case Command::Trace:    return cmd_trace(opt);
        case Command::SelfTest: return cmd_selftest(opt);
        default:                return 0;
    }
}

}  // namespace
}  // namespace ntptool

int main(int argc, char** argv) {
    using namespace ntptool;

    std::string err;
    if (!net_global_init(err)) {
        std::cerr << "fatal: " << err << "\n";
        return 3;
    }
    install_signal_handler();

    Options opt;
    if (!parse_cli(argc, argv, opt)) {
        std::cerr << "error: " << opt.error << "\n";
        std::cerr << "Try 'ntptool help' for usage.\n";
        net_global_cleanup();
        return 2;
    }

    // Resolve colour usage: honour --color/--no-color, otherwise auto-detect.
    bool want_color = !opt.no_color &&
                      (opt.color_forced || stream_is_tty(stdout));
    if (want_color) enable_virtual_terminal();
    opt.color.enabled = want_color;

    int rc = 0;
    if (opt.command == Command::Help) {
        if (opt.help_topic != Command::None)
            print_command_help(std::cout, opt.help_topic);
        else
            print_usage(std::cout);
    } else if (opt.command == Command::Version) {
        print_version(std::cout);
    } else if (opt.show_help) {
        print_command_help(std::cout, opt.command);
    } else {
        rc = dispatch(opt);
    }

    net_global_cleanup();
    return rc;
}
