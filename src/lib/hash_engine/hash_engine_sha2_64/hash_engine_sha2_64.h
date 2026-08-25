/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HASH_ENGINE_SHA2_64_H_
#define BOTAN_HASH_ENGINE_SHA2_64_H_

#include <botan/internal/hash_engine.h>

namespace Botan {

/**
* Create a multi-buffer SHA-512 family Hash_Engine
*
* Returns nullptr if the hash is not SHA-512/SHA-384/SHA-512-256
* (possibly truncated), if the requested provider does not match, or if
* no SIMD implementation is usable on this CPU.
*/
std::unique_ptr<Hash_Engine> create_sha2_64_mb_engine(std::string_view hash_fn,
                                                      std::span<const uint8_t> common_prefix,
                                                      std::string_view provider);

/*
* Multi-buffer SHA-512 compression functions
*
* The states buffer holds the 8 chaining variables for each lane, as
* little-endian words in variable-major order (all lanes of A, then all
* lanes of B, ...). blocks[l] points to the first of nblocks contiguous
* 128 byte blocks for lane l.
*
* The extract functions transpose the states into the 64 byte big-endian
* digest of each lane, stored contiguously in lane order.
*/

#if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_ARMV8)
/// Number of interleaved streams; the SHA-512 instructions form a
/// dependency chain per stream, which independent streams hide
inline constexpr size_t SHA2_64_ARMV8_STREAMS = 2;

void sha2_64_mb_compress_armv8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks);
void sha2_64_mb_extract_armv8(const uint8_t* states, uint8_t* digests);
#endif

#if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_AVX2)
void sha2_64_mb_compress_x4(uint8_t* states, const uint8_t* const* blocks, size_t nblocks);
void sha2_64_mb_extract_x4(const uint8_t* states, uint8_t* digests);
#endif

#if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_AVX512)
void sha2_64_mb_compress_x8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks);
void sha2_64_mb_extract_x8(const uint8_t* states, uint8_t* digests);
#endif

}  // namespace Botan

#endif
