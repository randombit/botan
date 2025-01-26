/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*     2023,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/uri.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <arpa/inet.h>
   #include <netinet/in.h>
   #include <sys/socket.h>
#elif defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   #include <ws2tcpip.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)

namespace Botan {

namespace {

bool is_domain_name(std::string_view domain) {
   try {
      check_and_canonicalize_dns_name(domain);
      return true;
   } catch(Decoding_Error&) {
      return false;
   }
}

bool is_ipv4(std::string_view ip) {
   std::string ip_str(ip);
   sockaddr_storage inaddr;
   return !!inet_pton(AF_INET, ip_str.c_str(), &inaddr);
}

bool is_ipv6(std::string_view ip) {
   std::string ip_str(ip);
   sockaddr_storage in6addr;
   return !!inet_pton(AF_INET6, ip_str.c_str(), &in6addr);
}

uint16_t parse_port_number(const char* func_name, std::string_view uri, size_t pos) {
   if(pos == std::string::npos || uri.empty()) {
      return 0;
   }

   BOTAN_ARG_CHECK(pos < uri.size(), "URI invalid port specifier");

   uint32_t port = 0;

   for(char c : uri.substr(pos + 1)) {
      size_t digit = c - '0';
      if(digit >= 10) {
         throw Invalid_Argument(fmt("URI::{} invalid port field in {}", func_name, uri));
      }
      port = port * 10 + (c - '0');
      if(port > 65535) {
         throw Invalid_Argument(fmt("URI::{} invalid port field in {}", func_name, uri));
      }
   }

   return static_cast<uint16_t>(port);
}

}  // namespace

URI URI::from_domain(std::string_view uri) {
   BOTAN_ARG_CHECK(!uri.empty(), "URI::from_domain empty URI is invalid");

   uint16_t port = 0;
   const auto port_pos = uri.find(':');
   if(port_pos != std::string::npos) {
      port = parse_port_number("from_domain", uri, port_pos);
   }
   const auto domain = uri.substr(0, port_pos);
   if(is_ipv4(domain)) {
      throw Invalid_Argument("URI::from_domain domain name should not be IP address");
   }
   if(!is_domain_name(domain)) {
      throw Invalid_Argument(fmt("URI::from_domain domain name '{}' not valid", domain));
   }

   return URI(Type::Domain, domain, port);
}

URI URI::from_ipv4(std::string_view uri) {
   BOTAN_ARG_CHECK(!uri.empty(), "URI::from_ipv4 empty URI is invalid");

   const auto port_pos = uri.find(':');
   const uint16_t port = parse_port_number("from_ipv4", uri, port_pos);
   const auto ip = uri.substr(0, port_pos);
   if(!is_ipv4(ip)) {
      throw Invalid_Argument("URI::from_ipv4: Invalid IPv4 specifier");
   }
   return URI(Type::IPv4, ip, port);
}

URI URI::from_ipv6(std::string_view uri) {
   BOTAN_ARG_CHECK(!uri.empty(), "URI::from_ipv6 empty URI is invalid");

   const auto port_pos = uri.find(']');
   const bool with_braces = (port_pos != std::string::npos);
   if((uri[0] == '[') != with_braces) {
      throw Invalid_Argument("URI::from_ipv6 Invalid IPv6 address with mismatch braces");
   }

   uint16_t port = 0;
   if(with_braces && (uri.size() > port_pos + 1)) {
      if(uri[port_pos + 1] != ':') {
         throw Invalid_Argument("URI::from_ipv6 Invalid IPv6 address");
      }

      port = parse_port_number("from_ipv6", uri, port_pos + 1);
   }
   const auto ip = uri.substr((with_braces ? 1 : 0), port_pos - with_braces);
   if(!is_ipv6(ip)) {
      throw Invalid_Argument("URI::from_ipv6 URI has invalid IPv6 address");
   }
   return URI(Type::IPv6, ip, port);
}

URI URI::from_any(std::string_view uri) {
   BOTAN_ARG_CHECK(!uri.empty(), "URI::from_any empty URI is invalid");

   try {
      return URI::from_ipv4(uri);
   } catch(Invalid_Argument&) {}

   try {
      return URI::from_ipv6(uri);
   } catch(Invalid_Argument&) {}

   return URI::from_domain(uri);
}

std::string URI::to_string() const {
   if(m_port != 0) {
      if(m_type == Type::IPv6) {
         return "[" + m_host + "]:" + std::to_string(m_port);
      }
      return m_host + ":" + std::to_string(m_port);
   }
   return m_host;
}

}  // namespace Botan

#else

namespace Botan {

URI URI::from_domain(std::string_view) {
   throw Not_Implemented("No socket support enabled in build");
}

URI URI::from_ipv4(std::string_view) {
   throw Not_Implemented("No socket support enabled in build");
}

URI URI::from_ipv6(std::string_view) {
   throw Not_Implemented("No socket support enabled in build");
}

URI URI::from_any(std::string_view) {
   throw Not_Implemented("No socket support enabled in build");
}

}  // namespace Botan

#endif
