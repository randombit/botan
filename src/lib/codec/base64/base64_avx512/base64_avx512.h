/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BASE64_AVX512_H_
#define BOTAN_BASE64_AVX512_H_

#include <botan/types.h>

namespace Botan {

/**
* Encode complete 48 byte groups of input, returning the number of
* input bytes consumed (a multiple of 48)
*/
size_t base64_encode_avx512(char out[], const uint8_t in[], size_t length);

/**
* Copy in to out, removing any of the whitespace characters that base64
* decoding ignores. Returns the number of bytes written.
*/
size_t base64_strip_ws_avx512(uint8_t out[], const uint8_t in[], size_t length);

/**
* Decode complete 64 character blocks, stopping early if any block
* contains a character that is not one of the 64 data characters
* (including padding and whitespace). Always leaves at least one block
* for the caller so that padding handling and error reporting stay in
* the scalar decoder. Returns the number of input characters consumed
* (a multiple of 64); output written is consumed/4*3 bytes.
*/
size_t base64_decode_avx512(uint8_t out[], const uint8_t in[], size_t length);

}  // namespace Botan

#endif
