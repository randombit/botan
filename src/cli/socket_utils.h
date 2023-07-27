/*
* (C) 2014,2017 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_SOCKET_UTILS_H_
#define BOTAN_CLI_SOCKET_UTILS_H_

#include "cli_exceptions.h"
#include <botan/types.h>
#include <cstring>

#if defined(BOTAN_TARGET_OS_HAS_WINSOCK2)

   #include <WS2tcpip.h>
   #include <winsock2.h>

typedef SOCKET socket_type;

inline socket_type invalid_socket() {
   return INVALID_SOCKET;
}

typedef size_t ssize_t;
typedef int sendrecv_len_type;

inline void close_socket(socket_type s) {
   ::closesocket(s);
}

   #define STDIN_FILENO _fileno(stdin)

inline void init_sockets() {
   WSAData wsa_data;
   WORD wsa_version = MAKEWORD(2, 2);

   if(::WSAStartup(wsa_version, &wsa_data) != 0) {
      throw Botan_CLI::CLI_Error("WSAStartup() failed: " + std::to_string(WSAGetLastError()));
   }

   if(LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
      ::WSACleanup();
      throw Botan_CLI::CLI_Error("Could not find a usable version of Winsock.dll");
   }
}

inline void stop_sockets() {
   ::WSACleanup();
}

inline std::string err_to_string(int e) {
   // TODO use strerror_s here
   return "Error code " + std::to_string(e);
}

inline int close(int fd) {
   return ::closesocket(fd);
}

inline int read(int s, void* buf, size_t len) {
   return ::recv(s, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
}

inline int send(int s, const uint8_t* buf, size_t len, int flags) {
   return ::send(s, reinterpret_cast<const char*>(buf), static_cast<int>(len), flags);
}

#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)

   #include <arpa/inet.h>
   #include <errno.h>
   #include <fcntl.h>
   #include <netdb.h>
   #include <netinet/in.h>
   #include <sys/socket.h>
   #include <sys/time.h>
   #include <sys/types.h>
   #include <unistd.h>

typedef int socket_type;
typedef size_t sendrecv_len_type;

inline socket_type invalid_socket() {
   return -1;
}

inline void close_socket(socket_type s) {
   ::close(s);
}

inline void init_sockets() {}

inline void stop_sockets() {}

inline std::string err_to_string(int e) {
   return std::strerror(e);
}

#endif

#if !defined(MSG_NOSIGNAL)
   #define MSG_NOSIGNAL 0
#endif

#endif
