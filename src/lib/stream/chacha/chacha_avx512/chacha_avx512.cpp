/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/chacha.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

//static
BOTAN_AVX512_FN
void ChaCha::chacha_avx512_x16(uint8_t output[64 * 16], uint32_t state[16], size_t rounds) {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");
   const SIMD_16x32 CTR0 = SIMD_16x32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

   const uint32_t C = 0xFFFFFFFF - state[12];
   const SIMD_16x32 CTR1 = SIMD_16x32(
      0, C < 1, C < 2, C < 3, C < 4, C < 5, C < 6, C < 7, C < 8, C < 9, C < 10, C < 11, C < 12, C < 13, C < 14, C < 15);

   SIMD_16x32 R00 = SIMD_16x32::splat(state[0]);
   SIMD_16x32 R01 = SIMD_16x32::splat(state[1]);
   SIMD_16x32 R02 = SIMD_16x32::splat(state[2]);
   SIMD_16x32 R03 = SIMD_16x32::splat(state[3]);
   SIMD_16x32 R04 = SIMD_16x32::splat(state[4]);
   SIMD_16x32 R05 = SIMD_16x32::splat(state[5]);
   SIMD_16x32 R06 = SIMD_16x32::splat(state[6]);
   SIMD_16x32 R07 = SIMD_16x32::splat(state[7]);
   SIMD_16x32 R08 = SIMD_16x32::splat(state[8]);
   SIMD_16x32 R09 = SIMD_16x32::splat(state[9]);
   SIMD_16x32 R10 = SIMD_16x32::splat(state[10]);
   SIMD_16x32 R11 = SIMD_16x32::splat(state[11]);
   SIMD_16x32 R12 = SIMD_16x32::splat(state[12]) + CTR0;
   SIMD_16x32 R13 = SIMD_16x32::splat(state[13]) + CTR1;
   SIMD_16x32 R14 = SIMD_16x32::splat(state[14]);
   SIMD_16x32 R15 = SIMD_16x32::splat(state[15]);

   for(size_t r = 0; r != rounds / 2; ++r) {
      R00 += R04;
      R01 += R05;
      R02 += R06;
      R03 += R07;

      R12 ^= R00;
      R13 ^= R01;
      R14 ^= R02;
      R15 ^= R03;

      R12 = R12.rotl<16>();
      R13 = R13.rotl<16>();
      R14 = R14.rotl<16>();
      R15 = R15.rotl<16>();

      R08 += R12;
      R09 += R13;
      R10 += R14;
      R11 += R15;

      R04 ^= R08;
      R05 ^= R09;
      R06 ^= R10;
      R07 ^= R11;

      R04 = R04.rotl<12>();
      R05 = R05.rotl<12>();
      R06 = R06.rotl<12>();
      R07 = R07.rotl<12>();

      R00 += R04;
      R01 += R05;
      R02 += R06;
      R03 += R07;

      R12 ^= R00;
      R13 ^= R01;
      R14 ^= R02;
      R15 ^= R03;

      R12 = R12.rotl<8>();
      R13 = R13.rotl<8>();
      R14 = R14.rotl<8>();
      R15 = R15.rotl<8>();

      R08 += R12;
      R09 += R13;
      R10 += R14;
      R11 += R15;

      R04 ^= R08;
      R05 ^= R09;
      R06 ^= R10;
      R07 ^= R11;

      R04 = R04.rotl<7>();
      R05 = R05.rotl<7>();
      R06 = R06.rotl<7>();
      R07 = R07.rotl<7>();

      R00 += R05;
      R01 += R06;
      R02 += R07;
      R03 += R04;

      R15 ^= R00;
      R12 ^= R01;
      R13 ^= R02;
      R14 ^= R03;

      R15 = R15.rotl<16>();
      R12 = R12.rotl<16>();
      R13 = R13.rotl<16>();
      R14 = R14.rotl<16>();

      R10 += R15;
      R11 += R12;
      R08 += R13;
      R09 += R14;

      R05 ^= R10;
      R06 ^= R11;
      R07 ^= R08;
      R04 ^= R09;

      R05 = R05.rotl<12>();
      R06 = R06.rotl<12>();
      R07 = R07.rotl<12>();
      R04 = R04.rotl<12>();

      R00 += R05;
      R01 += R06;
      R02 += R07;
      R03 += R04;

      R15 ^= R00;
      R12 ^= R01;
      R13 ^= R02;
      R14 ^= R03;

      R15 = R15.rotl<8>();
      R12 = R12.rotl<8>();
      R13 = R13.rotl<8>();
      R14 = R14.rotl<8>();

      R10 += R15;
      R11 += R12;
      R08 += R13;
      R09 += R14;

      R05 ^= R10;
      R06 ^= R11;
      R07 ^= R08;
      R04 ^= R09;

      R05 = R05.rotl<7>();
      R06 = R06.rotl<7>();
      R07 = R07.rotl<7>();
      R04 = R04.rotl<7>();
   }

   R00 += SIMD_16x32::splat(state[0]);
   R01 += SIMD_16x32::splat(state[1]);
   R02 += SIMD_16x32::splat(state[2]);
   R03 += SIMD_16x32::splat(state[3]);
   R04 += SIMD_16x32::splat(state[4]);
   R05 += SIMD_16x32::splat(state[5]);
   R06 += SIMD_16x32::splat(state[6]);
   R07 += SIMD_16x32::splat(state[7]);
   R08 += SIMD_16x32::splat(state[8]);
   R09 += SIMD_16x32::splat(state[9]);
   R10 += SIMD_16x32::splat(state[10]);
   R11 += SIMD_16x32::splat(state[11]);
   R12 += SIMD_16x32::splat(state[12]) + CTR0;
   R13 += SIMD_16x32::splat(state[13]) + CTR1;
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

   state[12] += 16;
   if(state[12] < 16) {
      state[13]++;
   }
}
}  // namespace Botan
