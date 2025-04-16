/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X509_UTILS_H_
#define BOTAN_X509_UTILS_H_

#include <botan/asn1_obj.h>
#include <initializer_list>
#include <optional>

namespace Botan {

inline std::optional<uint32_t> is_sub_element_of(const OID& oid, std::initializer_list<uint32_t> prefix) {
   const auto& c = oid.get_components();

   if(c.size() != prefix.size() + 1) {
      return {};
   }

   if(!std::equal(c.begin(), c.end() - 1, prefix.begin(), prefix.end())) {
      return {};
   }

   return c[c.size() - 1];
}

}  // namespace Botan

#endif
