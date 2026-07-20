#pragma once

// -----------------------------------------------------------------------------
// Project identity / version metadata.
// -----------------------------------------------------------------------------
#define NTPTOOL_NAME          "ntptool"
#define NTPTOOL_VERSION_MAJOR 1
#define NTPTOOL_VERSION_MINOR 0
#define NTPTOOL_VERSION_PATCH 0
#define NTPTOOL_VERSION       "1.0.0"

namespace ntptool {
inline const char* program_name() { return NTPTOOL_NAME; }
inline const char* version_string() { return NTPTOOL_VERSION; }
}  // namespace ntptool
