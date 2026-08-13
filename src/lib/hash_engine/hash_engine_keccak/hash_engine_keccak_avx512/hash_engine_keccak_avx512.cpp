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

namespace {

BOTAN_FN_ISA_SIMD_8X64 BOTAN_FORCE_INLINE void keccak_round(SIMD_8x64 T[25], const SIMD_8x64 A[25], uint64_t RC) {
   const auto C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
   const auto C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
   const auto C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
   const auto C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
   const auto C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

   const auto D0 = C0.rotl<1>() ^ C3;
   const auto D1 = C1.rotl<1>() ^ C4;
   const auto D2 = C2.rotl<1>() ^ C0;
   const auto D3 = C3.rotl<1>() ^ C1;
   const auto D4 = C4.rotl<1>() ^ C2;

   const auto B00 = A[0] ^ D1;
   const auto B01 = (A[6] ^ D2).rotl<44>();
   const auto B02 = (A[12] ^ D3).rotl<43>();
   const auto B03 = (A[18] ^ D4).rotl<21>();
   const auto B04 = (A[24] ^ D0).rotl<14>();
   T[0] = SIMD_8x64::chi(B00, B01, B02) ^ SIMD_8x64::splat(RC);
   T[1] = SIMD_8x64::chi(B01, B02, B03);
   T[2] = SIMD_8x64::chi(B02, B03, B04);
   T[3] = SIMD_8x64::chi(B03, B04, B00);
   T[4] = SIMD_8x64::chi(B04, B00, B01);

   const auto B05 = (A[3] ^ D4).rotl<28>();
   const auto B06 = (A[9] ^ D0).rotl<20>();
   const auto B07 = (A[10] ^ D1).rotl<3>();
   const auto B08 = (A[16] ^ D2).rotl<45>();
   const auto B09 = (A[22] ^ D3).rotl<61>();
   T[5] = SIMD_8x64::chi(B05, B06, B07);
   T[6] = SIMD_8x64::chi(B06, B07, B08);
   T[7] = SIMD_8x64::chi(B07, B08, B09);
   T[8] = SIMD_8x64::chi(B08, B09, B05);
   T[9] = SIMD_8x64::chi(B09, B05, B06);

   const auto B10 = (A[1] ^ D2).rotl<1>();
   const auto B11 = (A[7] ^ D3).rotl<6>();
   const auto B12 = (A[13] ^ D4).rotl<25>();
   const auto B13 = (A[19] ^ D0).rotl<8>();
   const auto B14 = (A[20] ^ D1).rotl<18>();
   T[10] = SIMD_8x64::chi(B10, B11, B12);
   T[11] = SIMD_8x64::chi(B11, B12, B13);
   T[12] = SIMD_8x64::chi(B12, B13, B14);
   T[13] = SIMD_8x64::chi(B13, B14, B10);
   T[14] = SIMD_8x64::chi(B14, B10, B11);

   const auto B15 = (A[4] ^ D0).rotl<27>();
   const auto B16 = (A[5] ^ D1).rotl<36>();
   const auto B17 = (A[11] ^ D2).rotl<10>();
   const auto B18 = (A[17] ^ D3).rotl<15>();
   const auto B19 = (A[23] ^ D4).rotl<56>();
   T[15] = SIMD_8x64::chi(B15, B16, B17);
   T[16] = SIMD_8x64::chi(B16, B17, B18);
   T[17] = SIMD_8x64::chi(B17, B18, B19);
   T[18] = SIMD_8x64::chi(B18, B19, B15);
   T[19] = SIMD_8x64::chi(B19, B15, B16);

   const auto B20 = (A[2] ^ D3).rotl<62>();
   const auto B21 = (A[8] ^ D4).rotl<55>();
   const auto B22 = (A[14] ^ D0).rotl<39>();
   const auto B23 = (A[15] ^ D1).rotl<41>();
   const auto B24 = (A[21] ^ D2).rotl<2>();
   T[20] = SIMD_8x64::chi(B20, B21, B22);
   T[21] = SIMD_8x64::chi(B21, B22, B23);
   T[22] = SIMD_8x64::chi(B22, B23, B24);
   T[23] = SIMD_8x64::chi(B23, B24, B20);
   T[24] = SIMD_8x64::chi(B24, B20, B21);
}

}  // namespace

BOTAN_FN_ISA_SIMD_8X64 void keccak_mb_permute_x8(uint64_t* states) {
   SIMD_8x64 A[25];
   SIMD_8x64 T[25];

   for(size_t w = 0; w != 25; ++w) {
      A[w] = SIMD_8x64::load_le(states + 8 * w);
   }

   for(size_t i = 0; i != 24; i += 2) {
      keccak_round(T, A, KECCAK_RC[i]);
      keccak_round(A, T, KECCAK_RC[i + 1]);
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
         keccak_round(T, A, KECCAK_RC[i]);
         keccak_round(A, T, KECCAK_RC[i + 1]);
      }
   }

   for(size_t w = 0; w != 25; ++w) {
      A[w].store_le(states + 8 * w);
   }
}

}  // namespace Botan
