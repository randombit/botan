/*
* (C) 2014,2017 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*     2025 Kagan Can Sit
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CLI_SOCKET_UTILS_H_
#define BOTAN_CLI_SOCKET_UTILS_H_

#include "cli_exceptions.h"
#include <botan/internal/socket_platform.h>

class Socket_Utils {
   public:
      // Re-export platform types for CLI usage
      using socket_type = Botan::OS::Socket_Platform::socket_type;
      using socket_op_ret_type = Botan::OS::Socket_Platform::socket_op_ret_type;
      using socklen_type = Botan::OS::Socket_Platform::socklen_type;
      using sendrecv_len_type = Botan::OS::Socket_Platform::sendrecv_len_type;

      // Socket operations
      [[nodiscard]] static socket_type invalid_socket() noexcept {
         return Botan::OS::Socket_Platform::invalid_socket();
      }

      static void close_socket(socket_type s) noexcept { Botan::OS::Socket_Platform::close_socket(s); }

      [[nodiscard]] static std::string get_last_error() { return Botan::OS::Socket_Platform::get_last_socket_error(); }

      static void set_nonblocking(socket_type s) { Botan::OS::Socket_Platform::set_nonblocking(s); }

      // Socket initialization
      static void init() { Botan::OS::Socket_Platform::socket_init(); }

      static void cleanup() noexcept { Botan::OS::Socket_Platform::socket_fini(); }

   private:
      Socket_Utils() = delete;  // Static class
      ~Socket_Utils() = delete;
};

#if !defined(MSG_NOSIGNAL)
   #define MSG_NOSIGNAL 0
#endif
#endif  // BOTAN_CLI_SOCKET_UTILS_H_
