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

}  // namespace Botan

#endif
