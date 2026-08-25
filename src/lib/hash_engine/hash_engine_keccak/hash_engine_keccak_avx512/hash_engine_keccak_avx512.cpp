/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_keccak.h>

#include <botan/assert.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/simd_8x64.h>

namespace Botan {

namespace {}  // namespace

BOTAN_FN_ISA_SIMD_8X64 void keccak_mb_permute_x8(uint64_t* states) {
   SIMD_8x64 A[25];
   SIMD_8x64 T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = SIMD_8x64::load_le(states + 8 * w);
   }

   for(size_t i = 0; i != 24; i += 2) {
      Keccak_Permutation_round(T, A, KECCAK_RC[i]);
      Keccak_Permutation_round(A, T, KECCAK_RC[i + 1]);
   }

   for(size_t w = 0; w != 25; ++w) {
      A[w].store_le(states + 8 * w);
   }
}

BOTAN_FN_ISA_SIMD_8X64 void keccak_mb_absorb_x8(uint64_t* states,
                                                const uint8_t* const* blocks,
                                                size_t rate_words,
                                                size_t nblocks) {
   SIMD_8x64 A[25];
   SIMD_8x64 T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = SIMD_8x64::load_le(states + 8 * w);
   }

   // The whole strip is staged into word-major lane order with scalar
   // loads and stores first; unlike an unpack based transpose these do
   // not compete with the permutation for the vector ports
   BOTAN_ASSERT_NOMSG(nblocks <= KECCAK_MB_ABSORB_BLOCKS && rate_words <= 25);

   alignas(64) uint64_t staged[KECCAK_MB_ABSORB_BLOCKS * 25 * 8];
   for(size_t b = 0; b != nblocks; ++b) {
      for(size_t l = 0; l != 8; ++l) {
         const uint8_t* src = blocks[8 * b + l];
         for(size_t w = 0; w != rate_words; ++w) {
            staged[(b * rate_words + w) * 8 + l] = load_le<uint64_t>(src, w);
         }
      }
   }

   for(size_t b = 0; b != nblocks; ++b) {
      for(size_t w = 0; w != rate_words; ++w) {
         A[w] ^= SIMD_8x64::load_le(staged + (b * rate_words + w) * 8);
      }

      for(size_t i = 0; i != 24; i += 2) {
         Keccak_Permutation_round(T, A, KECCAK_RC[i]);
         Keccak_Permutation_round(A, T, KECCAK_RC[i + 1]);
      }
   }

   for(size_t w = 0; w != 25; ++w) {
      A[w].store_le(states + 8 * w);
   }
}

}  // namespace Botan
