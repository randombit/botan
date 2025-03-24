/*
* Library-defined literals
* (C) 2025 Jack Lloyd
*     2025 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_LITERALS_H_
#define BOTAN_UTILS_LITERALS_H_

#include <botan/build.h>
#include <botan/concepts.h>

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

#if defined(BOTAN_HAS_ASN1)
   #include <botan/asn1_obj.h>
#endif

namespace Botan::literals {

#if defined(BOTAN_HAS_ASN1)

template <detail::StringLiteral str>
constexpr auto operator""_oid() {
   constexpr size_t oid_elements = std::count(std::begin(str.value), std::end(str.value), '.') + 1;
   using oid_array = std::array<uint32_t, oid_elements>;
   constexpr auto oid = [&]() -> std::optional<oid_array> {
      std::optional<uint32_t> elem;
      oid_array elems;
      auto current_elem = elems.begin();

      for(char c : str.value) {
         if(c == '.' || c == 0) {
            if(!elem) {
               return {};
            }

            *(current_elem++) = std::exchange(elem, {}).value();
         } else if(c >= '0' && c <= '9') {
            elem = elem.value_or(0) * 10 + (c - '0');
         } else {
            return {};
         }
      }

      return elems;
   }();

   static_assert(oid, "Failed to parse OID at compile time");
   return OID{*oid};
}

#endif

}  // namespace Botan::literals

#endif