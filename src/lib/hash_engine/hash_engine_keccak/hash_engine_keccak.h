/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HASH_ENGINE_KECCAK_H_
#define BOTAN_HASH_ENGINE_KECCAK_H_

#include <botan/internal/hash_engine.h>

namespace Botan {

/**
* Create a multi-buffer Keccak (SHAKE-128/256, SHA-3) Hash_Engine
*
* Returns nullptr if the hash is not Keccak based, if the requested
* provider does not match, or if no SIMD implementation is usable on
* this CPU.
*/
std::unique_ptr<Hash_Engine> create_keccak_mb_engine(std::string_view hash_fn,
                                                     std::span<const uint8_t> common_prefix,
                                                     std::string_view provider);

/*
* Multi-buffer Keccak-f[1600] permutations
*
* The states buffer holds the 25 Keccak words for each lane, in
* word-major order (all lanes of word 0, then all lanes of word 1, ...).
*
* The absorb variants keep the state in registers while absorbing and
* permuting nblocks rate blocks. blocks[b * lanes + l] points to the
* rate bytes of block b of lane l, which the kernel transposes into the
* word-major lane order as it absorbs. At most KECCAK_MB_ABSORB_BLOCKS
* blocks may be passed per call.
*/

inline constexpr size_t KECCAK_MB_ABSORB_BLOCKS = 8;

#if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX2)
void keccak_mb_permute_x4(uint64_t* states);
void keccak_mb_absorb_x4(uint64_t* states, const uint8_t* const* blocks, size_t rate_words, size_t nblocks);
#endif

#if defined(BOTAN_HAS_HASH_ENGINE_KECCAK_AVX512)
void keccak_mb_permute_x8(uint64_t* states);
void keccak_mb_absorb_x8(uint64_t* states, const uint8_t* const* blocks, size_t rate_words, size_t nblocks);
#endif

}  // namespace Botan

#endif
