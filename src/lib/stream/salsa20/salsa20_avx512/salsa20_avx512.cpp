/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/salsa20.h>

#include <botan/assert.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

//static
void BOTAN_FN_ISA_AVX512 Salsa20::salsa20_avx512_x16(uint8_t output[64 * 16], uint32_t state[16], size_t rounds) {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

   const SIMD_16x32 CTR_LO =
      SIMD_16x32::splat(state[8]) + SIMD_16x32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
   // Carry into the high counter word for lanes whose low word wrapped
   const SIMD_16x32 CTR_HI = SIMD_16x32::splat(state[9]) - CTR_LO.unsigned_lt(SIMD_16x32::splat(state[8]));

   SIMD_16x32 R00 = SIMD_16x32::splat(state[0]);
   SIMD_16x32 R01 = SIMD_16x32::splat(state[1]);
   SIMD_16x32 R02 = SIMD_16x32::splat(state[2]);
   SIMD_16x32 R03 = SIMD_16x32::splat(state[3]);
   SIMD_16x32 R04 = SIMD_16x32::splat(state[4]);
   SIMD_16x32 R05 = SIMD_16x32::splat(state[5]);
   SIMD_16x32 R06 = SIMD_16x32::splat(state[6]);
   SIMD_16x32 R07 = SIMD_16x32::splat(state[7]);
   SIMD_16x32 R08 = CTR_LO;
   SIMD_16x32 R09 = CTR_HI;
   SIMD_16x32 R10 = SIMD_16x32::splat(state[10]);
   SIMD_16x32 R11 = SIMD_16x32::splat(state[11]);
   SIMD_16x32 R12 = SIMD_16x32::splat(state[12]);
   SIMD_16x32 R13 = SIMD_16x32::splat(state[13]);
   SIMD_16x32 R14 = SIMD_16x32::splat(state[14]);
   SIMD_16x32 R15 = SIMD_16x32::splat(state[15]);

   for(size_t r = 0; r != rounds / 2; ++r) {
      // column round
      R04 ^= (R00 + R12).rotl<7>();
      R09 ^= (R05 + R01).rotl<7>();
      R14 ^= (R10 + R06).rotl<7>();
      R03 ^= (R15 + R11).rotl<7>();

      R08 ^= (R04 + R00).rotl<9>();
      R13 ^= (R09 + R05).rotl<9>();
      R02 ^= (R14 + R10).rotl<9>();
      R07 ^= (R03 + R15).rotl<9>();

      R12 ^= (R08 + R04).rotl<13>();
      R01 ^= (R13 + R09).rotl<13>();
      R06 ^= (R02 + R14).rotl<13>();
      R11 ^= (R07 + R03).rotl<13>();

      R00 ^= (R12 + R08).rotl<18>();
      R05 ^= (R01 + R13).rotl<18>();
      R10 ^= (R06 + R02).rotl<18>();
      R15 ^= (R11 + R07).rotl<18>();

      // row round
      R01 ^= (R00 + R03).rotl<7>();
      R06 ^= (R05 + R04).rotl<7>();
      R11 ^= (R10 + R09).rotl<7>();
      R12 ^= (R15 + R14).rotl<7>();

      R02 ^= (R01 + R00).rotl<9>();
      R07 ^= (R06 + R05).rotl<9>();
      R08 ^= (R11 + R10).rotl<9>();
      R13 ^= (R12 + R15).rotl<9>();

      R03 ^= (R02 + R01).rotl<13>();
      R04 ^= (R07 + R06).rotl<13>();
      R09 ^= (R08 + R11).rotl<13>();
      R14 ^= (R13 + R12).rotl<13>();

      R00 ^= (R03 + R02).rotl<18>();
      R05 ^= (R04 + R07).rotl<18>();
      R10 ^= (R09 + R08).rotl<18>();
      R15 ^= (R14 + R13).rotl<18>();
   }

   R00 += SIMD_16x32::splat(state[0]);
   R01 += SIMD_16x32::splat(state[1]);
   R02 += SIMD_16x32::splat(state[2]);
   R03 += SIMD_16x32::splat(state[3]);
   R04 += SIMD_16x32::splat(state[4]);
   R05 += SIMD_16x32::splat(state[5]);
   R06 += SIMD_16x32::splat(state[6]);
   R07 += SIMD_16x32::splat(state[7]);
   R08 += CTR_LO;
   R09 += CTR_HI;
   R10 += SIMD_16x32::splat(state[10]);
   R11 += SIMD_16x32::splat(state[11]);
   R12 += SIMD_16x32::splat(state[12]);
   R13 += SIMD_16x32::splat(state[13]);
   R14 += SIMD_16x32::splat(state[14]);
   R15 += SIMD_16x32::splat(state[15]);

   SIMD_16x32::transpose(R00, R01, R02, R03, R04, R05, R06, R07, R08, R09, R10, R11, R12, R13, R14, R15);

   R00.store_le(output);
   R01.store_le(output + 64 * 1);
   R02.store_le(output + 64 * 2);
   R03.store_le(output + 64 * 3);
   R04.store_le(output + 64 * 4);
   R05.store_le(output + 64 * 5);
   R06.store_le(output + 64 * 6);
   R07.store_le(output + 64 * 7);
   R08.store_le(output + 64 * 8);
   R09.store_le(output + 64 * 9);
   R10.store_le(output + 64 * 10);
   R11.store_le(output + 64 * 11);
   R12.store_le(output + 64 * 12);
   R13.store_le(output + 64 * 13);
   R14.store_le(output + 64 * 14);
   R15.store_le(output + 64 * 15);

   SIMD_16x32::zero_registers();

   state[8] += 16;
   if(state[8] < 16) {
      state[9]++;
   }
}
}  // namespace Botan
