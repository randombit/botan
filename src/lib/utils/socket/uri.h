/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*     2023,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_URI_H_
#define BOTAN_URI_H_

#include <botan/types.h>
#include <cstdint>
#include <string>
#include <string_view>

namespace Botan {

class BOTAN_TEST_API URI {
   public:
      enum class Type : uint8_t {
         IPv4,
         IPv6,
         Domain,
      };

      static URI from_any(std::string_view uri);
      static URI from_ipv4(std::string_view uri);
      static URI from_ipv6(std::string_view uri);
      static URI from_domain(std::string_view uri);

      URI(Type type, std::string_view host, uint16_t port) : m_type(type), m_host(host), m_port(port) {}

      bool operator==(const URI& a) const { return m_type == a.m_type && m_host == a.m_host && m_port == a.m_port; }

      std::string to_string() const;

      const std::string& host() const { return m_host; }

      uint16_t port() const { return m_port; }

      Type type() const { return m_type; }

   private:
      const Type m_type;
      const std::string m_host;
      const uint16_t m_port;
};

}  // namespace Botan

#endif
