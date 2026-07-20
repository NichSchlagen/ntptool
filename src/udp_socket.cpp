#include "ntptool/udp_socket.hpp"

#include <cstdio>
#include <cstring>
#include <utility>

#if defined(_WIN32)
#  include <io.h>  // _isatty / _fileno
#endif

namespace ntptool {

// ---------------------------------------------------------------------------
// Platform helpers (declared in platform.hpp)
// ---------------------------------------------------------------------------

bool net_global_init(std::string& err) {
#if defined(_WIN32)
    WSADATA wsa;
    int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (rc != 0) {
        err = "WSAStartup failed: " + socket_error_string(rc);
        return false;
    }
#else
    (void)err;
#endif
    return true;
}

void net_global_cleanup() {
#if defined(_WIN32)
    WSACleanup();
#endif
}

void close_socket(socket_t s) {
    if (s == kInvalidSocket) return;
#if defined(_WIN32)
    closesocket(s);
#else
    ::close(s);
#endif
}

int socket_last_error() {
#if defined(_WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

std::string socket_error_string(int code) {
#if defined(_WIN32)
    char* msg = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(code),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&msg), 0, nullptr);
    std::string out;
    if (n && msg) {
        out.assign(msg, n);
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                                out.back() == '.' || out.back() == ' '))
            out.pop_back();
    } else {
        out = "error " + std::to_string(code);
    }
    if (msg) LocalFree(msg);
    return out;
#else
    return std::strerror(code);
#endif
}

bool enable_virtual_terminal() {
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return false;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    return SetConsoleMode(h, mode) != 0;
#else
    return true;
#endif
}

bool stream_is_tty(void* file) {
    FILE* f = static_cast<FILE*>(file);
#if defined(_WIN32)
    return _isatty(_fileno(f)) != 0;
#else
    return isatty(fileno(f)) != 0;
#endif
}

// ---------------------------------------------------------------------------
// IpFamily
// ---------------------------------------------------------------------------

const char* ip_family_name(IpFamily f) {
    switch (f) {
        case IpFamily::Auto: return "auto";
        case IpFamily::IPv4: return "IPv4";
        case IpFamily::IPv6: return "IPv6";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

Endpoint::Endpoint(const sockaddr* sa, socklen_t len) {
    std::memset(&storage_, 0, sizeof(storage_));
    if (sa && len > 0 && len <= static_cast<socklen_t>(sizeof(storage_))) {
        std::memcpy(&storage_, sa, static_cast<size_t>(len));
        len_ = len;
    }
}

int Endpoint::family() const {
    return storage_.ss_family;
}

std::string Endpoint::ip() const {
    char host[NI_MAXHOST] = {0};
    if (len_ == 0) return "";
    int rc = getnameinfo(sockaddr_ptr(), len_, host, sizeof(host), nullptr, 0,
                         NI_NUMERICHOST);
    if (rc != 0) return "";
    return host;
}

uint16_t Endpoint::port() const {
    if (storage_.ss_family == AF_INET) {
        auto* s = reinterpret_cast<const sockaddr_in*>(&storage_);
        return ntohs(s->sin_port);
    } else if (storage_.ss_family == AF_INET6) {
        auto* s = reinterpret_cast<const sockaddr_in6*>(&storage_);
        return ntohs(s->sin6_port);
    }
    return 0;
}

std::string Endpoint::to_string() const {
    std::string h = ip();
    uint16_t p = port();
    if (storage_.ss_family == AF_INET6)
        return "[" + h + "]:" + std::to_string(p);
    return h + ":" + std::to_string(p);
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

std::vector<Endpoint> resolve(const std::string& host, uint16_t port,
                              IpFamily family, std::string& err) {
    std::vector<Endpoint> out;

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    switch (family) {
        case IpFamily::IPv4: hints.ai_family = AF_INET; break;
        case IpFamily::IPv6: hints.ai_family = AF_INET6; break;
        case IpFamily::Auto: hints.ai_family = AF_UNSPEC; break;
    }
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    std::string port_str = std::to_string(port);
    addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
#if defined(_WIN32)
        err = "resolve '" + host + "': " + socket_error_string(rc);
#else
        err = "resolve '" + host + "': " + gai_strerror(rc);
#endif
        return out;
    }
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        out.emplace_back(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen));
    }
    freeaddrinfo(res);
    if (out.empty()) err = "resolve '" + host + "': no addresses returned";
    return out;
}

// ---------------------------------------------------------------------------
// UdpSocket
// ---------------------------------------------------------------------------

UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& o) noexcept
    : fd_(o.fd_), timeout_(o.timeout_) {
    o.fd_ = kInvalidSocket;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        timeout_ = o.timeout_;
        o.fd_ = kInvalidSocket;
    }
    return *this;
}

bool UdpSocket::open(int family, std::string& err) {
    close();
    fd_ = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ == kInvalidSocket) {
        err = "socket(): " + socket_error_string(socket_last_error());
        return false;
    }
    set_recv_timeout(timeout_);
    return true;
}

void UdpSocket::close() {
    if (fd_ != kInvalidSocket) {
        close_socket(fd_);
        fd_ = kInvalidSocket;
    }
}

void UdpSocket::set_recv_timeout(std::chrono::milliseconds timeout) {
    timeout_ = timeout;
    if (fd_ == kInvalidSocket) return;
#if defined(_WIN32)
    DWORD ms = static_cast<DWORD>(timeout.count());
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&ms), sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

bool UdpSocket::send_to(const Endpoint& dst, const uint8_t* data, size_t len,
                        std::string& err) {
    if (fd_ == kInvalidSocket) {
        err = "socket not open";
        return false;
    }
#if defined(_WIN32)
    int n = sendto(fd_, reinterpret_cast<const char*>(data),
                   static_cast<int>(len), 0, dst.sockaddr_ptr(), dst.length());
    if (n == SOCKET_ERROR) {
#else
    ssize_t n = sendto(fd_, data, len, 0, dst.sockaddr_ptr(), dst.length());
    if (n < 0) {
#endif
        err = "sendto(): " + socket_error_string(socket_last_error());
        return false;
    }
    return true;
}

RecvStatus UdpSocket::recv_from(std::vector<uint8_t>& buf, Endpoint& from,
                                std::string& err) {
    if (fd_ == kInvalidSocket) {
        err = "socket not open";
        return RecvStatus::Error;
    }
    buf.assign(65535, 0);
    sockaddr_storage ss;
    std::memset(&ss, 0, sizeof(ss));
    socklen_t slen = sizeof(ss);

#if defined(_WIN32)
    int n = recvfrom(fd_, reinterpret_cast<char*>(buf.data()),
                     static_cast<int>(buf.size()), 0,
                     reinterpret_cast<sockaddr*>(&ss), &slen);
    if (n == SOCKET_ERROR) {
        int e = socket_last_error();
        if (e == WSAETIMEDOUT) return RecvStatus::Timeout;
        err = "recvfrom(): " + socket_error_string(e);
        return RecvStatus::Error;
    }
#else
    ssize_t n = recvfrom(fd_, buf.data(), buf.size(), 0,
                         reinterpret_cast<sockaddr*>(&ss), &slen);
    if (n < 0) {
        int e = socket_last_error();
        if (e == EAGAIN || e == EWOULDBLOCK) return RecvStatus::Timeout;
        err = "recvfrom(): " + socket_error_string(e);
        return RecvStatus::Error;
    }
#endif
    buf.resize(static_cast<size_t>(n));
    from = Endpoint(reinterpret_cast<sockaddr*>(&ss), slen);
    return RecvStatus::Ok;
}

}  // namespace ntptool
