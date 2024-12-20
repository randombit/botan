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
   constexpr auto result = detail::hex_decode_array(s.value);
   static_assert(result.second, "Failed to hex decode input literal");
   return result.first;
}

#endif

}  // namespace Botan::literals

#endif
