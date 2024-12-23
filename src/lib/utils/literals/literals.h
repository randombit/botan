/*
* Library-defined literals
* (C) 2024 Jack Lloyd
*     2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_LITERALS_H_
#define BOTAN_UTILS_LITERALS_H_

#include <botan/build.h>

#if defined(BOTAN_HAS_HEX_CODEC)
   #include <botan/hex.h>
#endif

namespace Botan::literals {

#if defined(BOTAN_HAS_HEX_CODEC)

/**
* Decode a hex string literal at compile time into a std::array
*/
template <detail::StringLiteral s>
consteval auto operator""_hex() {
   constexpr size_t total_chars = sizeof(s.value);
   constexpr size_t whitespace_chars = [] {
      // TODO: this could use the STL algorithm std::count_if, but GCC's
      //       iterator debugging broke the constexpr-ness of this approach.
      size_t res = 0;
      for(size_t i = 0; i < total_chars; ++i) {
         if(detail::is_hex_whitespace(s.value[i])) {
            ++res;
         }
      }
      return res;
   }();
   constexpr size_t hex_chars = total_chars - whitespace_chars;
   constexpr auto result = detail::hex_decode_array<total_chars, hex_chars>(s.value);
   static_assert(result.has_value(), "Failed to hex decode input literal");
   return result.value();
}

#endif

}  // namespace Botan::literals

#endif
