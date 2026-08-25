/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_keccak.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/keccak_perm_round.h>
#include <botan/internal/simd_4x64.h>

namespace Botan {

namespace {

/**
* XOR one rate block of each lane into the state, transposing from the
* per lane byte order into the word-major lane order. Any words past a
* multiple of the group size are handled by a final group overlapping
* the previous one, which requires rate_words >= 4 (the smallest rate,
* SHA-3-512, has 9 words).
*/
BOTAN_FN_ISA_SIMD_4X64 BOTAN_FORCE_INLINE void absorb_block(SIMD_4x64 A[25],
                                                            const uint8_t* const* blocks,
                                                            size_t rate_words) {
   const auto absorb4 = [&](size_t w0, size_t skip) {
      SIMD_4x64 M[4];
      for(size_t l = 0; l != 4; ++l) {
         M[l] = SIMD_4x64::load_le(blocks[l] + 8 * w0);
      }
      SIMD_4x64::transpose(M[0], M[1], M[2], M[3]);
      for(size_t w = skip; w != 4; ++w) {
         A[w0 + w] ^= M[w];
      }
   };

   size_t w = 0;
   for(; w + 4 <= rate_words; w += 4) {
      absorb4(w, 0);
   }
   if(w != rate_words) {
      absorb4(rate_words - 4, 4 - (rate_words - w));
   }
}

}  // namespace

BOTAN_FN_ISA_SIMD_4X64 void keccak_mb_permute_x4(uint64_t* states) {
   SIMD_4x64 A[25];
   SIMD_4x64 T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = SIMD_4x64::load_le(states + 4 * w);
   }

   for(size_t i = 0; i != 24; i += 2) {
      Keccak_Permutation_round(T, A, KECCAK_RC[i]);
      Keccak_Permutation_round(A, T, KECCAK_RC[i + 1]);
   }

   for(size_t w = 0; w != 25; ++w) {
      A[w].store_le(states + 4 * w);
   }
}

BOTAN_FN_ISA_SIMD_4X64 void keccak_mb_absorb_x4(uint64_t* states,
                                                const uint8_t* const* blocks,
                                                size_t rate_words,
                                                size_t nblocks) {
   SIMD_4x64 A[25];
   SIMD_4x64 T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = SIMD_4x64::load_le(states + 4 * w);
   }

   for(size_t b = 0; b != nblocks; ++b) {
      absorb_block(A, blocks + 4 * b, rate_words);

      for(size_t i = 0; i != 24; i += 2) {
         Keccak_Permutation_round(T, A, KECCAK_RC[i]);
         Keccak_Permutation_round(A, T, KECCAK_RC[i + 1]);
      }
   }

   for(size_t w = 0; w != 25; ++w) {
      A[w].store_le(states + 4 * w);
   }
}

}  // namespace Botan
