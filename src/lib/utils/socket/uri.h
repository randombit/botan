/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
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

struct BOTAN_TEST_API URI {
      enum class Type : uint8_t {
         NotSet,
         IPv4,
         IPv6,
         Domain,
      };
      static URI fromAny(std::string_view uri);
      static URI fromIPv4(std::string_view uri);
      static URI fromIPv6(std::string_view uri);
      static URI fromDomain(std::string_view uri);
      URI() = default;

      URI(Type xtype, std::string_view xhost, unsigned short xport) : type{xtype}, host{xhost}, port{xport} {}

      bool operator==(const URI& a) const { return type == a.type && host == a.host && port == a.port; }

      std::string to_string() const;

      const Type type{Type::NotSet};
      const std::string host{};
      const uint16_t port{};
};

}  // namespace Botan

#endif
