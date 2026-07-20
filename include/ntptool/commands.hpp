#pragma once

// -----------------------------------------------------------------------------
// Subcommand entry points. Each returns a process exit code.
// -----------------------------------------------------------------------------

#include "ntptool/cli.hpp"

namespace ntptool {

int cmd_query(const Options& opt);
int cmd_monitor(const Options& opt);
int cmd_compare(const Options& opt);
int cmd_scan(const Options& opt);
int cmd_control(const Options& opt);
int cmd_security(const Options& opt);
int cmd_trace(const Options& opt);
int cmd_selftest(const Options& opt);

// Shared: a flag set by the SIGINT handler so long-running commands can stop
// cleanly and still print their summary.
bool interrupted();
void install_signal_handler();

}  // namespace ntptool
