/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_keccak.h>

#include <botan/assert.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/keccak_perm_round.h>
#include <arm_neon.h>

namespace Botan {

namespace {

/**
* One Keccak-f[1600] round on two states, one per 64-bit lane, using the
* ARMv8.2 SHA-3 instructions: EOR3 for the column parities, RAX1 for the
* theta D values, XAR fusing the theta xor with the rho rotation, and
* BCAX which is exactly chi.
*
* The rotation of B is by rho as a left rotation; XAR rotates right, so
* the immediate is 64 minus the rho constant.
*/
BOTAN_FN_ISA_SHA3 BOTAN_FORCE_INLINE void keccak_round_x2(uint64x2_t T[25], const uint64x2_t A[25], uint64_t RC) {
   const uint64x2_t C0 = veor3q_u64(veor3q_u64(A[0], A[5], A[10]), A[15], A[20]);
   const uint64x2_t C1 = veor3q_u64(veor3q_u64(A[1], A[6], A[11]), A[16], A[21]);
   const uint64x2_t C2 = veor3q_u64(veor3q_u64(A[2], A[7], A[12]), A[17], A[22]);
   const uint64x2_t C3 = veor3q_u64(veor3q_u64(A[3], A[8], A[13]), A[18], A[23]);
   const uint64x2_t C4 = veor3q_u64(veor3q_u64(A[4], A[9], A[14]), A[19], A[24]);

   const uint64x2_t D0 = vrax1q_u64(C4, C1);
   const uint64x2_t D1 = vrax1q_u64(C0, C2);
   const uint64x2_t D2 = vrax1q_u64(C1, C3);
   const uint64x2_t D3 = vrax1q_u64(C2, C4);
   const uint64x2_t D4 = vrax1q_u64(C3, C0);

   const uint64x2_t B00 = veorq_u64(A[0], D0);
   const uint64x2_t B01 = vxarq_u64(A[6], D1, 64 - 44);
   const uint64x2_t B02 = vxarq_u64(A[12], D2, 64 - 43);
   const uint64x2_t B03 = vxarq_u64(A[18], D3, 64 - 21);
   const uint64x2_t B04 = vxarq_u64(A[24], D4, 64 - 14);
   T[0] = veorq_u64(vbcaxq_u64(B00, B02, B01), vdupq_n_u64(RC));
   T[1] = vbcaxq_u64(B01, B03, B02);
   T[2] = vbcaxq_u64(B02, B04, B03);
   T[3] = vbcaxq_u64(B03, B00, B04);
   T[4] = vbcaxq_u64(B04, B01, B00);

   const uint64x2_t B05 = vxarq_u64(A[3], D3, 64 - 28);
   const uint64x2_t B06 = vxarq_u64(A[9], D4, 64 - 20);
   const uint64x2_t B07 = vxarq_u64(A[10], D0, 64 - 3);
   const uint64x2_t B08 = vxarq_u64(A[16], D1, 64 - 45);
   const uint64x2_t B09 = vxarq_u64(A[22], D2, 64 - 61);
   T[5] = vbcaxq_u64(B05, B07, B06);
   T[6] = vbcaxq_u64(B06, B08, B07);
   T[7] = vbcaxq_u64(B07, B09, B08);
   T[8] = vbcaxq_u64(B08, B05, B09);
   T[9] = vbcaxq_u64(B09, B06, B05);

   const uint64x2_t B10 = vxarq_u64(A[1], D1, 64 - 1);
   const uint64x2_t B11 = vxarq_u64(A[7], D2, 64 - 6);
   const uint64x2_t B12 = vxarq_u64(A[13], D3, 64 - 25);
   const uint64x2_t B13 = vxarq_u64(A[19], D4, 64 - 8);
   const uint64x2_t B14 = vxarq_u64(A[20], D0, 64 - 18);
   T[10] = vbcaxq_u64(B10, B12, B11);
   T[11] = vbcaxq_u64(B11, B13, B12);
   T[12] = vbcaxq_u64(B12, B14, B13);
   T[13] = vbcaxq_u64(B13, B10, B14);
   T[14] = vbcaxq_u64(B14, B11, B10);

   const uint64x2_t B15 = vxarq_u64(A[4], D4, 64 - 27);
   const uint64x2_t B16 = vxarq_u64(A[5], D0, 64 - 36);
   const uint64x2_t B17 = vxarq_u64(A[11], D1, 64 - 10);
   const uint64x2_t B18 = vxarq_u64(A[17], D2, 64 - 15);
   const uint64x2_t B19 = vxarq_u64(A[23], D3, 64 - 56);
   T[15] = vbcaxq_u64(B15, B17, B16);
   T[16] = vbcaxq_u64(B16, B18, B17);
   T[17] = vbcaxq_u64(B17, B19, B18);
   T[18] = vbcaxq_u64(B18, B15, B19);
   T[19] = vbcaxq_u64(B19, B16, B15);

   const uint64x2_t B20 = vxarq_u64(A[2], D2, 64 - 62);
   const uint64x2_t B21 = vxarq_u64(A[8], D3, 64 - 55);
   const uint64x2_t B22 = vxarq_u64(A[14], D4, 64 - 39);
   const uint64x2_t B23 = vxarq_u64(A[15], D0, 64 - 41);
   const uint64x2_t B24 = vxarq_u64(A[21], D1, 64 - 2);
   T[20] = vbcaxq_u64(B20, B22, B21);
   T[21] = vbcaxq_u64(B21, B23, B22);
   T[22] = vbcaxq_u64(B22, B24, B23);
   T[23] = vbcaxq_u64(B23, B20, B24);
   T[24] = vbcaxq_u64(B24, B21, B20);
}

}  // namespace

BOTAN_FN_ISA_SHA3 void keccak_mb_permute_x2(uint64_t* states) {
   uint64x2_t A[25];
   uint64x2_t T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = vld1q_u64(states + 2 * w);
   }

   for(size_t i = 0; i != 24; i += 2) {
      keccak_round_x2(T, A, KECCAK_RC[i]);
      keccak_round_x2(A, T, KECCAK_RC[i + 1]);
   }

   for(size_t w = 0; w != 25; ++w) {
      vst1q_u64(states + 2 * w, A[w]);
   }
}

BOTAN_FN_ISA_SHA3 void keccak_mb_absorb_x2(uint64_t* states,
                                           const uint8_t* const* blocks,
                                           size_t rate_words,
                                           size_t nblocks) {
   BOTAN_ASSERT_NOMSG(nblocks <= KECCAK_MB_ABSORB_BLOCKS && rate_words >= 2 && rate_words <= 25);

   uint64x2_t A[25];
   uint64x2_t T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = vld1q_u64(states + 2 * w);
   }

   for(size_t b = 0; b != nblocks; ++b) {
      const uint8_t* p0 = blocks[2 * b];
      const uint8_t* p1 = blocks[2 * b + 1];

      // Absorbed in pairs of words; an odd final word is handled by an
      // overlapping pair xoring in only its new word
      for(size_t w = 0; w + 2 <= rate_words; w += 2) {
         const uint64x2_t g0 = vreinterpretq_u64_u8(vld1q_u8(p0 + 8 * w));
         const uint64x2_t g1 = vreinterpretq_u64_u8(vld1q_u8(p1 + 8 * w));
         A[w] = veorq_u64(A[w], vzip1q_u64(g0, g1));
         A[w + 1] = veorq_u64(A[w + 1], vzip2q_u64(g0, g1));
      }
      if(rate_words % 2 == 1) {
         const size_t w = rate_words - 2;
         const uint64x2_t g0 = vreinterpretq_u64_u8(vld1q_u8(p0 + 8 * w));
         const uint64x2_t g1 = vreinterpretq_u64_u8(vld1q_u8(p1 + 8 * w));
         A[w + 1] = veorq_u64(A[w + 1], vzip2q_u64(g0, g1));
      }

      for(size_t i = 0; i != 24; i += 2) {
         keccak_round_x2(T, A, KECCAK_RC[i]);
         keccak_round_x2(A, T, KECCAK_RC[i + 1]);
      }
   }

   for(size_t w = 0; w != 25; ++w) {
      vst1q_u64(states + 2 * w, A[w]);
   }
}

}  // namespace Botan
