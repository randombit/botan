/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/simd_avx2.h>
#include <botan/internal/stack_scrubbing.h>

#include <immintrin.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_4x32 alignr4(const SIMD_4x32& a, const SIMD_4x32& b) {
   return SIMD_4x32(_mm_alignr_epi8(a.raw(), b.raw(), 4));
}

template <size_t S>
BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_4x32 shr64(const SIMD_4x32& a) {
   return SIMD_4x32(_mm_srli_epi64(a.raw(), S));
}

template <uint8_t S>
BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_4x32 shuffle_32(const SIMD_4x32& a) {
   return SIMD_4x32(_mm_shuffle_epi32(a.raw(), S));
}

BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_8x32 alignr4(const SIMD_8x32& a, const SIMD_8x32& b) {
   return SIMD_8x32(_mm256_alignr_epi8(a.raw(), b.raw(), 4));
}

template <size_t S>
BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_8x32 shr64(const SIMD_8x32& a) {
   return SIMD_8x32(_mm256_srli_epi64(a.raw(), S));
}

template <uint8_t S>
BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_8x32 shuffle_32(const SIMD_8x32& a) {
   return SIMD_8x32(_mm256_shuffle_epi32(a.raw(), S));
}

template <typename SIMD_T>
BOTAN_FN_ISA_AVX2_BMI2 BOTAN_FORCE_INLINE SIMD_T next_w(SIMD_T x[4]) {
   constexpr size_t sigma0_0 = 7;
   constexpr size_t sigma0_1 = 18;
   constexpr size_t sigma0_2 = 3;
   constexpr size_t sigma1_0 = 17;
   constexpr size_t sigma1_1 = 19;
   constexpr size_t sigma1_2 = 10;

   const SIMD_T lo_mask = SIMD_T(0x03020100, 0x0b0a0908, 0x80808080, 0x80808080);
   const SIMD_T hi_mask = SIMD_T(0x80808080, 0x80808080, 0x03020100, 0x0b0a0908);

   auto t0 = alignr4(x[1], x[0]);
   x[0] += alignr4(x[3], x[2]);

   auto t1 = t0.template shl<32 - sigma0_1>();
   auto t2 = t0.template shr<sigma0_0>();
   auto t3 = t0.template shr<sigma0_2>();
   t0 = t3 ^ t2;

   t3 = shuffle_32<0b11111010>(x[3]);
   t2 = t2.template shr<sigma0_1 - sigma0_0>();
   t0 ^= t1 ^ t2;
   t1 = t1.template shl<sigma0_1 - sigma0_0>();
   t2 = t3.template shr<sigma1_2>();
   t3 = shr64<sigma1_0>(t3);
   x[0] += t0 ^ t1;

   t2 ^= t3;
   t3 = shr64<sigma1_1 - sigma1_0>(t3);
   x[0] += SIMD_T::byte_shuffle(t2 ^ t3, lo_mask);

   t3 = shuffle_32<0b01010000>(x[0]);
   t2 = t3.template shr<sigma1_2>();
   t3 = shr64<sigma1_0>(t3);
   t2 ^= t3;
   t3 = shr64<sigma1_1 - sigma1_0>(t3);
   x[0] += SIMD_T::byte_shuffle(t2 ^ t3, hi_mask);

   const auto tmp = x[0];
   x[0] = x[1];
   x[1] = x[2];
   x[2] = x[3];
   x[3] = tmp;

   return x[3];
}

}  // namespace

BOTAN_FN_ISA_AVX2_BMI2 BOTAN_SCRUB_STACK_AFTER_RETURN void SHA_256::compress_digest_x86_avx2(
   digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   // clang-format off

   alignas(64) const uint32_t K[64] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

   alignas(64) const uint32_t K2[2 * 64] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
      0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
      0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
      0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
      0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
      0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
      0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
      0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
      0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

   // clang-format on

   alignas(64) uint32_t W[16];
   alignas(64) uint32_t W2[64];

   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];
   uint32_t F = digest[5];
   uint32_t G = digest[6];
   uint32_t H = digest[7];

   const uint8_t* data = input.data();

   while(blocks >= 2) {
      SIMD_8x32 WS[4];

      for(size_t i = 0; i < 4; i++) {
         WS[i] = SIMD_8x32::load_be128(&data[16 * i], &data[64 + 16 * i]);
         auto WK = WS[i] + SIMD_8x32::load_le(&K2[8 * i]);
         WK.store_le128(&W[4 * i], &W2[4 * i]);
      }

      data += 2 * 64;
      blocks -= 2;

      for(size_t r = 0; r != 48; r += 16) {
         auto w = next_w(WS) + SIMD_8x32::load_le(&K2[2 * (r + 16)]);

         SHA2_32_F(A, B, C, D, E, F, G, H, W[0]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W[1]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W[2]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W[3]);

         w.store_le128(&W[0], &W2[r + 16]);

         w = next_w(WS) + SIMD_8x32::load_le(&K2[2 * (r + 20)]);

         SHA2_32_F(E, F, G, H, A, B, C, D, W[4]);
         SHA2_32_F(D, E, F, G, H, A, B, C, W[5]);
         SHA2_32_F(C, D, E, F, G, H, A, B, W[6]);
         SHA2_32_F(B, C, D, E, F, G, H, A, W[7]);

         w.store_le128(&W[4], &W2[r + 20]);

         w = next_w(WS) + SIMD_8x32::load_le(&K2[2 * (r + 24)]);

         SHA2_32_F(A, B, C, D, E, F, G, H, W[8]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W[9]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W[10]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W[11]);

         w.store_le128(&W[8], &W2[r + 24]);

         w = next_w(WS) + SIMD_8x32::load_le(&K2[2 * (r + 28)]);

         SHA2_32_F(E, F, G, H, A, B, C, D, W[12]);
         SHA2_32_F(D, E, F, G, H, A, B, C, W[13]);
         SHA2_32_F(C, D, E, F, G, H, A, B, W[14]);
         SHA2_32_F(B, C, D, E, F, G, H, A, W[15]);

         w.store_le128(&W[12], &W2[r + 28]);
      }

      SHA2_32_F(A, B, C, D, E, F, G, H, W[0]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[1]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[2]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[3]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[4]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[5]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[6]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[7]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[8]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[9]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);

      // Now the second block, with already expanded message
      SHA2_32_F(A, B, C, D, E, F, G, H, W2[0]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[1]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[2]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[3]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[4]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[5]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[6]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[7]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W2[8]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[9]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[10]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[11]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[12]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[13]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[14]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[15]);

      SHA2_32_F(A, B, C, D, E, F, G, H, W2[16]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[17]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[18]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[19]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[20]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[21]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[22]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[23]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W2[24]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[25]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[26]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[27]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[28]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[29]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[30]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[31]);

      SHA2_32_F(A, B, C, D, E, F, G, H, W2[32]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[33]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[34]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[35]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[36]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[37]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[38]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[39]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W2[40]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[41]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[42]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[43]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[44]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[45]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[46]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[47]);

      SHA2_32_F(A, B, C, D, E, F, G, H, W2[48]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[49]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[50]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[51]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[52]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[53]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[54]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[55]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W2[56]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W2[57]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W2[58]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W2[59]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W2[60]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W2[61]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W2[62]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W2[63]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);
   }

   while(blocks > 0) {
      SIMD_4x32 WS[4];

      for(size_t i = 0; i < 4; i++) {
         WS[i] = SIMD_4x32::load_be(&data[16 * i]);
         auto WK = WS[i] + SIMD_4x32::load_le(&K[4 * i]);
         WK.store_le(&W[4 * i]);
      }

      data += 64;
      blocks -= 1;

      for(size_t r = 0; r != 48; r += 16) {
         auto w = next_w(WS) + SIMD_4x32::load_le(&K[r + 16]);

         SHA2_32_F(A, B, C, D, E, F, G, H, W[0]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W[1]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W[2]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W[3]);

         w.store_le(&W[0]);

         w = next_w(WS) + SIMD_4x32::load_le(&K[r + 20]);

         SHA2_32_F(E, F, G, H, A, B, C, D, W[4]);
         SHA2_32_F(D, E, F, G, H, A, B, C, W[5]);
         SHA2_32_F(C, D, E, F, G, H, A, B, W[6]);
         SHA2_32_F(B, C, D, E, F, G, H, A, W[7]);

         w.store_le(&W[4]);

         w = next_w(WS) + SIMD_4x32::load_le(&K[r + 24]);

         SHA2_32_F(A, B, C, D, E, F, G, H, W[8]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W[9]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W[10]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W[11]);

         w.store_le(&W[8]);

         w = next_w(WS) + SIMD_4x32::load_le(&K[r + 28]);

         SHA2_32_F(E, F, G, H, A, B, C, D, W[12]);
         SHA2_32_F(D, E, F, G, H, A, B, C, W[13]);
         SHA2_32_F(C, D, E, F, G, H, A, B, W[14]);
         SHA2_32_F(B, C, D, E, F, G, H, A, W[15]);

         w.store_le(&W[12]);
      }

      SHA2_32_F(A, B, C, D, E, F, G, H, W[0]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[1]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[2]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[3]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[4]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[5]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[6]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[7]);
      SHA2_32_F(A, B, C, D, E, F, G, H, W[8]);
      SHA2_32_F(H, A, B, C, D, E, F, G, W[9]);
      SHA2_32_F(G, H, A, B, C, D, E, F, W[10]);
      SHA2_32_F(F, G, H, A, B, C, D, E, W[11]);
      SHA2_32_F(E, F, G, H, A, B, C, D, W[12]);
      SHA2_32_F(D, E, F, G, H, A, B, C, W[13]);
      SHA2_32_F(C, D, E, F, G, H, A, B, W[14]);
      SHA2_32_F(B, C, D, E, F, G, H, A, W[15]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);
   }
}

}  // namespace Botan
