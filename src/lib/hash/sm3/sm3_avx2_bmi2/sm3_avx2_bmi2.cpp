/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm3.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/simd_avx2.h>
#include <botan/internal/sm3_fn.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_8x32 alignr12(const SIMD_8x32& a, const SIMD_8x32& b) {
   return SIMD_8x32(_mm256_alignr_epi8(a.raw(), b.raw(), 12));
}

BOTAN_FN_ISA_AVX2_BMI2 inline SIMD_4x32 alignr12(const SIMD_4x32& a, const SIMD_4x32& b) {
   return SIMD_4x32(_mm_alignr_epi8(a.raw(), b.raw(), 12));
}

template <typename SIMD_T>
BOTAN_FN_ISA_AVX2_BMI2 inline void next_SM3_W(SIMD_T& W0, const SIMD_T& W1, const SIMD_T& W2, const SIMD_T& W3) {
   auto X3 = alignr12(W1, W0);                     // W[3..6]
   auto X7 = alignr12(W2, W1);                     // W[7..10]
   auto X10 = SIMD_T::alignr8(W3, W2);             // W[10..13]
   auto X13 = W3.template shift_elems_right<1>();  // W[13..15] || 0

   auto P1_I = W0 ^ X7 ^ X13.template rotl<15>();
   auto P1_O = P1_I ^ P1_I.template rotl<15>() ^ P1_I.template rotl<23>();
   auto T = P1_O ^ X3.template rotl<7>() ^ X10;

   /*
   * There is one hole in the recurrence, we now must compute P1(rotl<15>(W[0]))
   * and xor it into W[3]
   */

   // Extract W[0] into T2 in position 3
   auto T2 = T.template shift_elems_left<3>();

   // Compute P1(rotl<15>(W[0])) [combining the rotation values]
   auto P1_T2 = T2.template rotl<15>() ^ T2.template rotl<30>() ^ T2.template rotl<6>();

   // XOR in
   T ^= P1_T2;

   W0 = T;
}

}  // namespace

BOTAN_FN_ISA_AVX2_BMI2 void SM3::compress_digest_x86_avx2(digest_type& digest,
                                                          std::span<const uint8_t> input,
                                                          size_t blocks) {
   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];
   uint32_t F = digest[5];
   uint32_t G = digest[6];
   uint32_t H = digest[7];
   std::array<uint32_t, 16> W{};
   std::array<uint32_t, 68> E2{};

   const uint8_t* data = input.data();

   // NOLINTBEGIN(*-container-data-pointer)

   while(blocks >= 2) {
      auto W0 = SIMD_8x32::load_be128(&data[0], &data[64]);
      auto W1 = SIMD_8x32::load_be128(&data[16], &data[80]);
      auto W2 = SIMD_8x32::load_be128(&data[32], &data[96]);
      auto W3 = SIMD_8x32::load_be128(&data[48], &data[112]);

      W0.store_le128(&W[0], &E2[0]);
      W1.store_le128(&W[4], &E2[4]);
      W2.store_le128(&W[8], &E2[8]);
      W3.store_le128(&W[12], &E2[12]);

      data += 2 * block_bytes;
      blocks -= 2;

      // clang-format off

      R1(A, B, C, D, E, F, G, H, 0x79CC4519, W[ 0], W[ 4]);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, W[ 1], W[ 5]);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, W[ 2], W[ 6]);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le128(&W[0], &E2[16]);

      R1(A, B, C, D, E, F, G, H, 0x9CC45197, W[ 4], W[ 8]);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, W[ 5], W[ 9]);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, W[ 6], W[10]);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W[ 7], W[11]);
      next_SM3_W(W1, W2, W3, W0);
      W1.store_le128(&W[4], &E2[20]);

      R1(A, B, C, D, E, F, G, H, 0xCC451979, W[ 8], W[12]);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, W[ 9], W[13]);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, W[10], W[14]);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W[11], W[15]);
      next_SM3_W(W2, W3, W0, W1);
      W2.store_le128(&W[8], &E2[24]);

      R1(A, B, C, D, E, F, G, H, 0xC451979C, W[12], W[ 0]);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, W[13], W[ 1]);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, W[14], W[ 2]);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W[15], W[ 3]);
      next_SM3_W(W3, W0, W1, W2);
      W3.store_le128(&W[12], &E2[28]);

      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le128(&W[0], &E2[32]);

      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);
      next_SM3_W(W1, W2, W3, W0);
      W1.store_le128(&W[4], &E2[36]);

      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);
      next_SM3_W(W2, W3, W0, W1);
      W2.store_le128(&W[8], &E2[40]);

      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);
      next_SM3_W(W3, W0, W1, W2);
      W3.store_le128(&W[12], &E2[44]);

      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le128(&W[0], &E2[48]);

      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W[ 7], W[11]);
      next_SM3_W(W1, W2, W3, W0);
      W1.store_le128(&W[4], &E2[52]);

      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W[11], W[15]);
      next_SM3_W(W2, W3, W0, W1);
      W2.store_le128(&W[8], &E2[56]);

      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W[15], W[ 3]);
      next_SM3_W(W3, W0, W1, W2);
      W3.store_le128(&W[12], &E2[60]);

      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le128(&W[0], &E2[64]);

      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);

      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);

      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);

      // clang-format on

      A = (digest[0] ^= A);
      B = (digest[1] ^= B);
      C = (digest[2] ^= C);
      D = (digest[3] ^= D);
      E = (digest[4] ^= E);
      F = (digest[5] ^= F);
      G = (digest[6] ^= G);
      H = (digest[7] ^= H);

      // clang-format off
      R1(A, B, C, D, E, F, G, H, 0x79CC4519, E2[0], E2[4]);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, E2[1], E2[5]);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, E2[2], E2[6]);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, E2[3], E2[7]);
      R1(A, B, C, D, E, F, G, H, 0x9CC45197, E2[4], E2[8]);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, E2[5], E2[9]);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, E2[6], E2[10]);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, E2[7], E2[11]);
      R1(A, B, C, D, E, F, G, H, 0xCC451979, E2[8], E2[12]);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, E2[9], E2[13]);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, E2[10], E2[14]);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, E2[11], E2[15]);
      R1(A, B, C, D, E, F, G, H, 0xC451979C, E2[12], E2[16]);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, E2[13], E2[17]);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, E2[14], E2[18]);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, E2[15], E2[19]);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, E2[16], E2[20]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, E2[17], E2[21]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, E2[18], E2[22]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, E2[19], E2[23]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, E2[20], E2[24]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, E2[21], E2[25]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, E2[22], E2[26]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, E2[23], E2[27]);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, E2[24], E2[28]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, E2[25], E2[29]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, E2[26], E2[30]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, E2[27], E2[31]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, E2[28], E2[32]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, E2[29], E2[33]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, E2[30], E2[34]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, E2[31], E2[35]);
      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, E2[32], E2[36]);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, E2[33], E2[37]);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, E2[34], E2[38]);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, E2[35], E2[39]);
      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, E2[36], E2[40]);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, E2[37], E2[41]);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, E2[38], E2[42]);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, E2[39], E2[43]);
      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, E2[40], E2[44]);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, E2[41], E2[45]);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, E2[42], E2[46]);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, E2[43], E2[47]);
      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, E2[44], E2[48]);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, E2[45], E2[49]);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, E2[46], E2[50]);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, E2[47], E2[51]);
      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, E2[48], E2[52]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, E2[49], E2[53]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, E2[50], E2[54]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, E2[51], E2[55]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, E2[52], E2[56]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, E2[53], E2[57]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, E2[54], E2[58]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, E2[55], E2[59]);
      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, E2[56], E2[60]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, E2[57], E2[61]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, E2[58], E2[62]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, E2[59], E2[63]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, E2[60], E2[64]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, E2[61], E2[65]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, E2[62], E2[66]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, E2[63], E2[67]);

      // clang-format on

      A = (digest[0] ^= A);
      B = (digest[1] ^= B);
      C = (digest[2] ^= C);
      D = (digest[3] ^= D);
      E = (digest[4] ^= E);
      F = (digest[5] ^= F);
      G = (digest[6] ^= G);
      H = (digest[7] ^= H);
   }

   while(blocks > 0) {
      SIMD_4x32 W0 = SIMD_4x32::load_be(&data[0]);
      SIMD_4x32 W1 = SIMD_4x32::load_be(&data[16]);
      SIMD_4x32 W2 = SIMD_4x32::load_be(&data[32]);
      SIMD_4x32 W3 = SIMD_4x32::load_be(&data[48]);

      W0.store_le(&W[0]);
      W1.store_le(&W[4]);
      W2.store_le(&W[8]);
      W3.store_le(&W[12]);

      data += block_bytes;
      blocks -= 1;

      // clang-format off

      R1(A, B, C, D, E, F, G, H, 0x79CC4519, W[ 0], W[ 4]);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, W[ 1], W[ 5]);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, W[ 2], W[ 6]);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le(&W[0]);

      R1(A, B, C, D, E, F, G, H, 0x9CC45197, W[ 4], W[ 8]);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, W[ 5], W[ 9]);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, W[ 6], W[10]);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W[ 7], W[11]);
      next_SM3_W(W1, W2, W3, W0);
      W1.store_le(&W[4]);

      R1(A, B, C, D, E, F, G, H, 0xCC451979, W[ 8], W[12]);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, W[ 9], W[13]);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, W[10], W[14]);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W[11], W[15]);
      next_SM3_W(W2, W3, W0, W1);
      W2.store_le(&W[8]);

      R1(A, B, C, D, E, F, G, H, 0xC451979C, W[12], W[ 0]);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, W[13], W[ 1]);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, W[14], W[ 2]);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W[15], W[ 3]);
      next_SM3_W(W3, W0, W1, W2);
      W3.store_le(&W[12]);

      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le(&W[0]);

      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);
      next_SM3_W(W1, W2, W3, W0);
      W1.store_le(&W[4]);

      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);
      next_SM3_W(W2, W3, W0, W1);
      W2.store_le(&W[8]);

      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);
      next_SM3_W(W3, W0, W1, W2);
      W3.store_le(&W[12]);

      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le(&W[0]);

      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W[ 7], W[11]);
      next_SM3_W(W1, W2, W3, W0);
      W1.store_le(&W[4]);

      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W[11], W[15]);
      next_SM3_W(W2, W3, W0, W1);
      W2.store_le(&W[8]);

      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W[15], W[ 3]);
      next_SM3_W(W3, W0, W1, W2);
      W3.store_le(&W[12]);

      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]);
      next_SM3_W(W0, W1, W2, W3);
      W0.store_le(&W[0]);

      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);

      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);

      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);

      // clang-format on

      A = (digest[0] ^= A);
      B = (digest[1] ^= B);
      C = (digest[2] ^= C);
      D = (digest[3] ^= D);
      E = (digest[4] ^= E);
      F = (digest[5] ^= F);
      G = (digest[6] ^= G);
      H = (digest[7] ^= H);
   }

   // NOLINTEND(*-container-data-pointer)
}

}  // namespace Botan
