/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CAMELLIA_GFNI_H_
#define BOTAN_CAMELLIA_GFNI_H_

#include <botan/types.h>
#include <span>

namespace Botan {

void camellia_gfni_encrypt9(const uint8_t in[], uint8_t out[], size_t blocks, std::span<const uint64_t> SK);

void camellia_gfni_encrypt12(const uint8_t in[], uint8_t out[], size_t blocks, std::span<const uint64_t> SK);

void camellia_gfni_decrypt9(const uint8_t in[], uint8_t out[], size_t blocks, std::span<const uint64_t> SK);

void camellia_gfni_decrypt12(const uint8_t in[], uint8_t out[], size_t blocks, std::span<const uint64_t> SK);

}  // namespace Botan

#endif
