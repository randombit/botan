/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KDF_XMD_H_
#define BOTAN_KDF_XMD_H_

#include <botan/types.h>
#include <span>

namespace Botan {

class HashFunction;

/**
* XMD hash function from RFC 9380
*
* This is only used internally to implement hash2curve so is not
* exposed to end users.
*
* The hash must be in its initial state. The caller is responsible for
* checking that the hash is strong enough for the target security level,
* as required by RFC 9380.
*/
void BOTAN_TEST_API expand_message_xmd(HashFunction& hash,
                                       std::span<uint8_t> output,
                                       std::span<const uint8_t> input,
                                       std::span<const uint8_t> domain_sep);

}  // namespace Botan

#endif
