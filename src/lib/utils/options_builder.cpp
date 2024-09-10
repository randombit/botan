/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/options_builder.h>

#include <botan/hex.h>
#include <botan/internal/fmt.h>

#if defined(BOTAN_HAS_HASH)
   #include <botan/hash.h>
#endif

#if defined(BOTAN_HAS_MAC)
   #include <botan/mac.h>
#endif

namespace Botan::detail::BuilderOptionHelper {

std::string to_string(const std::unique_ptr<HashFunction>& value) {
#if defined(BOTAN_HAS_HASH)
   if(value) {
      return value->name();
   } else {
      return "nullptr";
   }
#else
   BOTAN_UNUSED(value);
   return "hash function not available";
#endif
}

std::string to_string(const std::unique_ptr<MessageAuthenticationCode>& value) {
#if defined(BOTAN_HAS_MAC)
   if(value) {
      return value->name();
   } else {
      return "nullptr";
   }
#else
   BOTAN_UNUSED(value);
   return "MAC not available";
#endif
}

std::string to_string(std::span<const uint8_t> value) {
   constexpr size_t max_printable_length = 64;
   if(value.empty()) {
      return "empty";
   }

   auto str = hex_encode(value.first(std::min(value.size(), max_printable_length)));
   if(value.size() > max_printable_length) {
      str += Botan::fmt("... ({} more bytes)", value.size() - max_printable_length);
   }

   return str;
}

}  // namespace Botan::detail::BuilderOptionHelper
