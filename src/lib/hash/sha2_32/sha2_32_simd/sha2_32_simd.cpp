/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/rotate.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/stack_scrubbing.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_SIMD_4X32 BOTAN_FORCE_INLINE SIMD_4x32 sha256_simd_next_w(SIMD_4x32 x[4]) {
   const SIMD_4x32 lo_mask = SIMD_4x32(0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000);
   const SIMD_4x32 hi_mask = SIMD_4x32(0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);

   const SIMD_4x32 lo_word_shuf = SIMD_4x32(0x03020100, 0x07060504, 0x03020100, 0x07060504);
   const SIMD_4x32 hi_word_shuf = SIMD_4x32(0x0B0A0908, 0x0F0E0D0C, 0x0B0A0908, 0x0F0E0D0C);

   auto t0 = SIMD_4x32::alignr4(x[1], x[0]);
   x[0] += SIMD_4x32::alignr4(x[3], x[2]);

   x[0] += t0.rotr<7>() ^ t0.rotr<18>() ^ t0.shr<3>();

   t0 = SIMD_4x32::byte_shuffle(x[3], hi_word_shuf);
   auto s1 = t0.rotr<17>() ^ t0.rotr<19>() ^ t0.shr<10>();
   x[0] += s1 & lo_mask;

   t0 = SIMD_4x32::byte_shuffle(x[0], lo_word_shuf);
   s1 = t0.rotr<17>() ^ t0.rotr<19>() ^ t0.shr<10>();
   x[0] += s1 & hi_mask;

   const auto tmp = x[0];
   x[0] = x[1];
   x[1] = x[2];
   x[2] = x[3];
   x[3] = tmp;

   return x[3];
}

}  // namespace

void BOTAN_FN_ISA_SIMD_4X32 BOTAN_SCRUB_STACK_AFTER_RETURN
SHA_256::compress_digest_x86_simd(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
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

   // clang-format on

   alignas(64) uint32_t W[16];

   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];
   uint32_t F = digest[5];
   uint32_t G = digest[6];
   uint32_t H = digest[7];

   const uint8_t* data = input.data();

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
         auto w = sha256_simd_next_w(WS) + SIMD_4x32::load_le(&K[r + 16]);

         SHA2_32_F(A, B, C, D, E, F, G, H, W[0]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W[1]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W[2]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W[3]);

         w.store_le(&W[0]);

         w = sha256_simd_next_w(WS) + SIMD_4x32::load_le(&K[r + 20]);

         SHA2_32_F(E, F, G, H, A, B, C, D, W[4]);
         SHA2_32_F(D, E, F, G, H, A, B, C, W[5]);
         SHA2_32_F(C, D, E, F, G, H, A, B, W[6]);
         SHA2_32_F(B, C, D, E, F, G, H, A, W[7]);

         w.store_le(&W[4]);

         w = sha256_simd_next_w(WS) + SIMD_4x32::load_le(&K[r + 24]);

         SHA2_32_F(A, B, C, D, E, F, G, H, W[8]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W[9]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W[10]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W[11]);

         w.store_le(&W[8]);

         w = sha256_simd_next_w(WS) + SIMD_4x32::load_le(&K[r + 28]);

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
