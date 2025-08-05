/*
* MGF1
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MGF1_H_
#define BOTAN_MGF1_H_

#include <botan/types.h>
#include <span>

namespace Botan {

class HashFunction;

/**
* MGF1 from PKCS #1 v2.0
* @param hash hash function to use
* @param input - the input buffer
* @param output - the output buffer. The buffer is XORed with the output of MGF1.
*/
void mgf1_mask(HashFunction& hash, std::span<const uint8_t> input, std::span<uint8_t> output);

}  // namespace Botan

#endif
