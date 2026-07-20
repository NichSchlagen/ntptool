#pragma once

// -----------------------------------------------------------------------------
// Thin, cross-platform UDP socket + DNS resolution wrapper.
// -----------------------------------------------------------------------------

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "ntptool/platform.hpp"

namespace ntptool {

enum class IpFamily { Auto, IPv4, IPv6 };

const char* ip_family_name(IpFamily f);

// A resolved transport address (wraps sockaddr_storage).
class Endpoint {
public:
    Endpoint() { std::memset(&storage_, 0, sizeof(storage_)); }
    Endpoint(const sockaddr* sa, socklen_t len);

    const sockaddr* sockaddr_ptr() const {
        return reinterpret_cast<const sockaddr*>(&storage_);
    }
    sockaddr* sockaddr_ptr() { return reinterpret_cast<sockaddr*>(&storage_); }
    socklen_t length() const { return len_; }
    void set_length(socklen_t l) { len_ = l; }

    int family() const;
    std::string ip() const;        // numeric host only
    uint16_t port() const;
    std::string to_string() const; // "ip:port" / "[ip6]:port"

    bool valid() const { return len_ != 0; }

private:
    sockaddr_storage storage_;
    socklen_t len_ = 0;
};

// DNS resolution. On failure returns an empty vector and fills `err`.
std::vector<Endpoint> resolve(const std::string& host, uint16_t port,
                              IpFamily family, std::string& err);

enum class RecvStatus { Ok, Timeout, Error };

// A connection-less UDP socket.
class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& o) noexcept;
    UdpSocket& operator=(UdpSocket&& o) noexcept;

    // Open a datagram socket for the given address family (AF_INET/AF_INET6,
    // derived from the endpoint you intend to talk to).
    bool open(int family, std::string& err);
    void close();
    bool is_open() const { return fd_ != kInvalidSocket; }

    void set_recv_timeout(std::chrono::milliseconds timeout);

    bool send_to(const Endpoint& dst, const uint8_t* data, size_t len,
                 std::string& err);

    // Receive a datagram (up to 65535 bytes). On success `buf` is resized to the
    // number of bytes read and `from` describes the sender.
    RecvStatus recv_from(std::vector<uint8_t>& buf, Endpoint& from,
                         std::string& err);

private:
    socket_t fd_ = kInvalidSocket;
    std::chrono::milliseconds timeout_{2000};
};

}  // namespace ntptool
