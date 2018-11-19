/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <botan/internal/simd_avx2.h>

namespace Botan {

//static
BOTAN_FUNC_ISA("avx2")
void ChaCha::chacha_avx2_x8(uint8_t output[64*8], uint32_t state[16], size_t rounds)
   {
   SIMD_8x32::reset_registers();

   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");
   const SIMD_8x32 CTR0 = SIMD_8x32(0, 1, 2, 3, 4, 5, 6, 7);

   const uint32_t C = 0xFFFFFFFF - state[12];
   const SIMD_8x32 CTR1 = SIMD_8x32(0, C < 1, C < 2, C < 3, C < 4, C < 5, C < 6, C < 7);

   SIMD_8x32 R00 = SIMD_8x32::splat(state[ 0]);
   SIMD_8x32 R01 = SIMD_8x32::splat(state[ 1]);
   SIMD_8x32 R02 = SIMD_8x32::splat(state[ 2]);
   SIMD_8x32 R03 = SIMD_8x32::splat(state[ 3]);
   SIMD_8x32 R04 = SIMD_8x32::splat(state[ 4]);
   SIMD_8x32 R05 = SIMD_8x32::splat(state[ 5]);
   SIMD_8x32 R06 = SIMD_8x32::splat(state[ 6]);
   SIMD_8x32 R07 = SIMD_8x32::splat(state[ 7]);
   SIMD_8x32 R08 = SIMD_8x32::splat(state[ 8]);
   SIMD_8x32 R09 = SIMD_8x32::splat(state[ 9]);
   SIMD_8x32 R10 = SIMD_8x32::splat(state[10]);
   SIMD_8x32 R11 = SIMD_8x32::splat(state[11]);
   SIMD_8x32 R12 = SIMD_8x32::splat(state[12]) + CTR0;
   SIMD_8x32 R13 = SIMD_8x32::splat(state[13]) + CTR1;
   SIMD_8x32 R14 = SIMD_8x32::splat(state[14]);
   SIMD_8x32 R15 = SIMD_8x32::splat(state[15]);

   for(size_t r = 0; r != rounds / 2; ++r)
      {
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

   R00 += SIMD_8x32::splat(state[0]);
   R01 += SIMD_8x32::splat(state[1]);
   R02 += SIMD_8x32::splat(state[2]);
   R03 += SIMD_8x32::splat(state[3]);
   R04 += SIMD_8x32::splat(state[4]);
   R05 += SIMD_8x32::splat(state[5]);
   R06 += SIMD_8x32::splat(state[6]);
   R07 += SIMD_8x32::splat(state[7]);
   R08 += SIMD_8x32::splat(state[8]);
   R09 += SIMD_8x32::splat(state[9]);
   R10 += SIMD_8x32::splat(state[10]);
   R11 += SIMD_8x32::splat(state[11]);
   R12 += SIMD_8x32::splat(state[12]) + CTR0;
   R13 += SIMD_8x32::splat(state[13]) + CTR1;
   R14 += SIMD_8x32::splat(state[14]);
   R15 += SIMD_8x32::splat(state[15]);

   SIMD_8x32::transpose(R00, R01, R02, R03);
   SIMD_8x32::transpose(R04, R05, R06, R07);
   SIMD_8x32::transpose(R08, R09, R10, R11);
   SIMD_8x32::transpose(R12, R13, R14, R15);

   __m256i* output_mm = reinterpret_cast<__m256i*>(output);

   _mm256_storeu_si256(output_mm     , _mm256_permute2x128_si256(R00.handle(), R04.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  1, _mm256_permute2x128_si256(R08.handle(), R12.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  2, _mm256_permute2x128_si256(R01.handle(), R05.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  3, _mm256_permute2x128_si256(R09.handle(), R13.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  4, _mm256_permute2x128_si256(R02.handle(), R06.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  5, _mm256_permute2x128_si256(R10.handle(), R14.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  6, _mm256_permute2x128_si256(R03.handle(), R07.handle(), 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  7, _mm256_permute2x128_si256(R11.handle(), R15.handle(), 0 + (2 << 4)));

   _mm256_storeu_si256(output_mm +  8, _mm256_permute2x128_si256(R00.handle(), R04.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  9, _mm256_permute2x128_si256(R08.handle(), R12.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm + 10, _mm256_permute2x128_si256(R01.handle(), R05.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm + 11, _mm256_permute2x128_si256(R09.handle(), R13.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm + 12, _mm256_permute2x128_si256(R02.handle(), R06.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm + 13, _mm256_permute2x128_si256(R10.handle(), R14.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm + 14, _mm256_permute2x128_si256(R03.handle(), R07.handle(), 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm + 15, _mm256_permute2x128_si256(R11.handle(), R15.handle(), 1 + (3 << 4)));

   SIMD_8x32::zero_registers();

   state[12] += 8;
   if(state[12] < 8)
      state[13]++;
   }
}
