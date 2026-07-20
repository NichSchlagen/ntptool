#pragma once

// -----------------------------------------------------------------------------
// Cross-platform networking abstraction layer.
//
// Hides the differences between the Winsock2 and the BSD socket APIs behind a
// small, uniform surface used by the rest of the code base.
// -----------------------------------------------------------------------------

#include <cstdint>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <cerrno>
#  include <cstring>
#endif

namespace ntptool {

#if defined(_WIN32)
using socket_t = SOCKET;
inline constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
inline constexpr socket_t kInvalidSocket = -1;
#endif

// One-time process wide network stack initialisation (WSAStartup on Windows,
// no-op elsewhere). Safe to call once from main().
bool net_global_init(std::string& err);
void net_global_cleanup();

// Close a socket in a platform independent way.
void close_socket(socket_t s);

// Last socket error code and its human readable representation.
int socket_last_error();
std::string socket_error_string(int code);

// Enable ANSI/VT100 escape sequence processing on the current console. On
// non-Windows platforms this is a no-op that always succeeds.
bool enable_virtual_terminal();

// Returns true when the given C FILE* refers to an interactive terminal.
bool stream_is_tty(void* file);

}  // namespace ntptool
