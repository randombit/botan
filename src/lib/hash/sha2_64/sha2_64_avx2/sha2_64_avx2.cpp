/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/simd_2x64.h>
#include <botan/internal/simd_4x64.h>

namespace Botan {

namespace {

template <typename SIMD_T>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_BMI2 SIMD_T sha512_next_w(SIMD_T x[8]) {
   auto t0 = SIMD_T::alignr8(x[1], x[0]);
   auto t1 = SIMD_T::alignr8(x[5], x[4]);

   auto s0 = t0.template rotr<1>() ^ t0.template rotr<8>() ^ t0.template shr<7>();
   auto s1 = x[7].template rotr<19>() ^ x[7].template rotr<61>() ^ x[7].template shr<6>();

   auto nx = x[0] + s0 + s1 + t1;

   x[0] = x[1];
   x[1] = x[2];
   x[2] = x[3];
   x[3] = x[4];
   x[4] = x[5];
   x[5] = x[6];
   x[6] = x[7];
   x[7] = nx;

   return x[7];
}

}  // namespace

BOTAN_FN_ISA_AVX2_BMI2 void SHA_512::compress_digest_x86_avx2(digest_type& digest,
                                                              std::span<const uint8_t> input,
                                                              size_t blocks) {
   alignas(64) uint64_t W[16] = {0};
   alignas(64) uint64_t W2[80];

   uint64_t A = digest[0];
   uint64_t B = digest[1];
   uint64_t C = digest[2];
   uint64_t D = digest[3];
   uint64_t E = digest[4];
   uint64_t F = digest[5];
   uint64_t G = digest[6];
   uint64_t H = digest[7];

   const uint8_t* data = input.data();

   while(blocks >= 2) {
      SIMD_4x64 WS[8];

      for(size_t i = 0; i < 8; i++) {
         WS[i] = SIMD_4x64::load_be2(&data[16 * i], &data[128 + 16 * i]);
         auto WK = WS[i] + SIMD_4x64::broadcast_2x64(&SHA512_K[2 * i]);
         WK.store_le2(&W[2 * i], &W2[2 * i]);
      }

      data += 2 * 128;
      blocks -= 2;

      // First 64 rounds of SHA-512
      for(size_t r = 0; r != 64; r += 16) {
         auto w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 16]);
         SHA2_64_F(A, B, C, D, E, F, G, H, W[0]);
         SHA2_64_F(H, A, B, C, D, E, F, G, W[1]);
         w.store_le2(&W[0], &W2[r + 16]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 18]);
         SHA2_64_F(G, H, A, B, C, D, E, F, W[2]);
         SHA2_64_F(F, G, H, A, B, C, D, E, W[3]);
         w.store_le2(&W[2], &W2[r + 18]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 20]);
         SHA2_64_F(E, F, G, H, A, B, C, D, W[4]);
         SHA2_64_F(D, E, F, G, H, A, B, C, W[5]);
         w.store_le2(&W[4], &W2[r + 20]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 22]);
         SHA2_64_F(C, D, E, F, G, H, A, B, W[6]);
         SHA2_64_F(B, C, D, E, F, G, H, A, W[7]);
         w.store_le2(&W[6], &W2[r + 22]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 24]);
         SHA2_64_F(A, B, C, D, E, F, G, H, W[8]);
         SHA2_64_F(H, A, B, C, D, E, F, G, W[9]);
         w.store_le2(&W[8], &W2[r + 24]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 26]);
         SHA2_64_F(G, H, A, B, C, D, E, F, W[10]);
         SHA2_64_F(F, G, H, A, B, C, D, E, W[11]);
         w.store_le2(&W[10], &W2[r + 26]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 28]);
         SHA2_64_F(E, F, G, H, A, B, C, D, W[12]);
         SHA2_64_F(D, E, F, G, H, A, B, C, W[13]);
         w.store_le2(&W[12], &W2[r + 28]);

         w = sha512_next_w(WS) + SIMD_4x64::broadcast_2x64(&SHA512_K[r + 30]);
         SHA2_64_F(C, D, E, F, G, H, A, B, W[14]);
         SHA2_64_F(B, C, D, E, F, G, H, A, W[15]);
         w.store_le2(&W[14], &W2[r + 30]);
      }

      // Final 16 rounds of SHA-512
      SHA2_64_F(A, B, C, D, E, F, G, H, W[0]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[1]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[2]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[3]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[4]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[5]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[6]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[7]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[8]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[9]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);

      // Second block of SHA-512 compression, with pre-expanded message
      SHA2_64_F(A, B, C, D, E, F, G, H, W2[0]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[1]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[2]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[3]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[4]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[5]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[6]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[7]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W2[8]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[9]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[10]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[11]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[12]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[13]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[14]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[15]);

      SHA2_64_F(A, B, C, D, E, F, G, H, W2[16]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[17]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[18]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[19]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[20]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[21]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[22]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[23]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W2[24]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[25]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[26]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[27]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[28]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[29]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[30]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[31]);

      SHA2_64_F(A, B, C, D, E, F, G, H, W2[32]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[33]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[34]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[35]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[36]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[37]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[38]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[39]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W2[40]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[41]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[42]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[43]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[44]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[45]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[46]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[47]);

      SHA2_64_F(A, B, C, D, E, F, G, H, W2[48]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[49]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[50]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[51]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[52]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[53]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[54]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[55]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W2[56]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[57]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[58]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[59]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[60]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[61]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[62]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[63]);

      SHA2_64_F(A, B, C, D, E, F, G, H, W2[64]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[65]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[66]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[67]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[68]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[69]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[70]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[71]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W2[72]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W2[73]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W2[74]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W2[75]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W2[76]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W2[77]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W2[78]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W2[79]);

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
      SIMD_2x64 WS[8];

      for(size_t i = 0; i < 8; i++) {
         WS[i] = SIMD_2x64::load_be(&data[16 * i]);
         auto WK = WS[i] + SIMD_2x64::load_le(&SHA512_K[2 * i]);
         WK.store_le(&W[2 * i]);
      }

      data += 128;
      blocks -= 1;

      // First 64 rounds of SHA-512
      for(size_t r = 0; r != 64; r += 16) {
         auto w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 16]);
         SHA2_64_F(A, B, C, D, E, F, G, H, W[0]);
         SHA2_64_F(H, A, B, C, D, E, F, G, W[1]);
         w.store_le(&W[0]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 18]);
         SHA2_64_F(G, H, A, B, C, D, E, F, W[2]);
         SHA2_64_F(F, G, H, A, B, C, D, E, W[3]);
         w.store_le(&W[2]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 20]);
         SHA2_64_F(E, F, G, H, A, B, C, D, W[4]);
         SHA2_64_F(D, E, F, G, H, A, B, C, W[5]);
         w.store_le(&W[4]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 22]);
         SHA2_64_F(C, D, E, F, G, H, A, B, W[6]);
         SHA2_64_F(B, C, D, E, F, G, H, A, W[7]);
         w.store_le(&W[6]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 24]);
         SHA2_64_F(A, B, C, D, E, F, G, H, W[8]);
         SHA2_64_F(H, A, B, C, D, E, F, G, W[9]);
         w.store_le(&W[8]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 26]);
         SHA2_64_F(G, H, A, B, C, D, E, F, W[10]);
         SHA2_64_F(F, G, H, A, B, C, D, E, W[11]);
         w.store_le(&W[10]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 28]);
         SHA2_64_F(E, F, G, H, A, B, C, D, W[12]);
         SHA2_64_F(D, E, F, G, H, A, B, C, W[13]);
         w.store_le(&W[12]);

         w = sha512_next_w(WS) + SIMD_2x64::load_le(&SHA512_K[r + 30]);
         SHA2_64_F(C, D, E, F, G, H, A, B, W[14]);
         SHA2_64_F(B, C, D, E, F, G, H, A, W[15]);
         w.store_le(&W[14]);
      }

      // Final 16 rounds of SHA-512
      SHA2_64_F(A, B, C, D, E, F, G, H, W[0]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[1]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[2]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[3]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[4]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[5]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[6]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[7]);
      SHA2_64_F(A, B, C, D, E, F, G, H, W[8]);
      SHA2_64_F(H, A, B, C, D, E, F, G, W[9]);
      SHA2_64_F(G, H, A, B, C, D, E, F, W[10]);
      SHA2_64_F(F, G, H, A, B, C, D, E, W[11]);
      SHA2_64_F(E, F, G, H, A, B, C, D, W[12]);
      SHA2_64_F(D, E, F, G, H, A, B, C, W[13]);
      SHA2_64_F(C, D, E, F, G, H, A, B, W[14]);
      SHA2_64_F(B, C, D, E, F, G, H, A, W[15]);

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
