/*
* Socket Platform
* (C) 2015,2016,2017 Jack Lloyd
*     2016 Daniel Neus
*     2025 Kagan Can Sit
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SOCKET_PLATFORM_H_
#define BOTAN_SOCKET_PLATFORM_H_

#include <botan/exceptn.h>
#include <botan/types.h>
#include <botan/internal/target_info.h>
#include <memory>
#include <string>
#include <system_error>

// Platform specific includes
#if defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   #include <winsock2.h>
   #include <ws2tcpip.h>
#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <errno.h>
   #include <fcntl.h>
   #include <netdb.h>
   #include <netinet/in.h>
   #include <string.h>
   #include <sys/socket.h>
   #include <sys/time.h>
   #include <unistd.h>
#endif

namespace Botan::OS::Socket_Platform {

#if defined(BOTAN_TARGET_OS_HAS_WINSOCK2)

using socket_type = SOCKET;
using socket_op_ret_type = int;
using socklen_type = int;
using sendrecv_len_type = int;

[[nodiscard]] inline socket_type invalid_socket() noexcept {
   return INVALID_SOCKET;
}

inline void close_socket(socket_type s) noexcept {
   if(s != invalid_socket()) {
      ::closesocket(s);
   }
}

[[nodiscard]] inline bool nonblocking_connect_in_progress() noexcept {
   return (::WSAGetLastError() == WSAEWOULDBLOCK);
}

inline void set_nonblocking(socket_type s) {
   u_long nonblocking = 1;
   if(::ioctlsocket(s, FIONBIO, &nonblocking) != 0) {
      throw System_Error("Setting socket to non-blocking state failed", ::WSAGetLastError());
   }
}

inline void socket_init() {
   WSAData wsa_data;
   WORD wsa_version = MAKEWORD(2, 2);

   if(::WSAStartup(wsa_version, &wsa_data) != 0) {
      throw System_Error("WSAStartup() failed", WSAGetLastError());
   }

   if(LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
      ::WSACleanup();
      throw System_Error("Could not find a usable version of Winsock.dll");
   }
}

inline void socket_fini() noexcept {
   ::WSACleanup();
}

#elif defined(BOTAN_TARGET_OS_HAS_SOCKETS)

using socket_type = int;
using socket_op_ret_type = ssize_t;
using socklen_type = socklen_t;
using sendrecv_len_type = size_t;

// Platform-specific implementations
[[nodiscard]] inline socket_type invalid_socket() noexcept {
   return -1;
}

inline void close_socket(socket_type s) noexcept {
   if(s != invalid_socket()) {
      ::close(s);
   }
}

[[nodiscard]] inline bool nonblocking_connect_in_progress() noexcept {
   return (errno == EINPROGRESS);
}

inline void set_nonblocking(socket_type s) {
   // NOLINTNEXTLINE(*-vararg)
   if(::fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
      throw System_Error("Setting socket to non-blocking state failed", errno);
   }
}

// Posix does not require initialization
inline void socket_init() {}

inline void socket_fini() noexcept {}
#endif

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
using unique_addrinfo_ptr = std::unique_ptr<addrinfo, decltype([](addrinfo* p) {
                                               if(p != nullptr) {
                                                  ::freeaddrinfo(p);
                                               }
                                            })>;
#endif

// Platform-independent functions
[[nodiscard]] inline std::string get_last_socket_error() {
   std::error_code ec(errno, std::generic_category());
   return ec.message();
}
}  // namespace Botan::OS::Socket_Platform
#endif  // BOTAN_SOCKET_PLATFORM_H
