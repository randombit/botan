/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KDF_XMD_H_
#define BOTAN_KDF_XMD_H_

#include <botan/types.h>
#include <span>
#include <string_view>

namespace Botan {

/**
* XMD hash function from RFC 9380
*
* This is only used internally to implement hash2curve so is not
* exposed to end users.
*/
void BOTAN_TEST_API expand_message_xmd(std::string_view hash_fn,
                                       std::span<uint8_t> output,
                                       std::span<const uint8_t> input,
                                       std::span<const uint8_t> domain_sep);

inline void expand_message_xmd(std::string_view hash_fn,
                               std::span<uint8_t> output,
                               std::string_view input_str,
                               std::string_view domain_sep_str) {
   std::span<const uint8_t> input(reinterpret_cast<const uint8_t*>(input_str.data()), input_str.size());

   std::span<const uint8_t> domain_sep(reinterpret_cast<const uint8_t*>(domain_sep_str.data()), domain_sep_str.size());

   expand_message_xmd(hash_fn, output, input, domain_sep);
}

}  // namespace Botan

#endif
