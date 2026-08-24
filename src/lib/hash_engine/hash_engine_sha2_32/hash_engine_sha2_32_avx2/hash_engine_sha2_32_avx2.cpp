/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_8x32.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void rnd(const SIMD_8x32& A,
                                              const SIMD_8x32& B,
                                              const SIMD_8x32& C,
                                              SIMD_8x32& D,
                                              const SIMD_8x32& E,
                                              const SIMD_8x32& F,
                                              const SIMD_8x32& G,
                                              SIMD_8x32& H,
                                              const SIMD_8x32& W,
                                              uint32_t K) {
   const auto T1 = H + E.sigma1() + SIMD_8x32::choose(E, F, G) + SIMD_8x32::splat(K) + W;
   const auto T2 = A.sigma0() + SIMD_8x32::majority(A, B, C);
   D += T1;
   H = T1 + T2;
}

BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE SIMD_8x32 next_w(SIMD_8x32 W[16], size_t i) {
   const auto& w15 = W[(i + 1) % 16];
   const auto& w2 = W[(i + 14) % 16];
   const auto s0 = w15.rotr<7>() ^ w15.rotr<18>() ^ w15.shr<3>();
   const auto s1 = w2.rotr<17>() ^ w2.rotr<19>() ^ w2.shr<10>();
   W[i] += s0 + s1 + W[(i + 9) % 16];
   return W[i];
}

}  // namespace

BOTAN_FN_ISA_AVX2 void sha2_32_mb_compress_x8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   alignas(64) const uint32_t SHA256_K[64] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

   SIMD_8x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_8x32::load_le(states + 32 * j);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // Initialized directly from the loads, since default construction
      // would zero the whole array first
      auto load_w = [&](size_t l, size_t off) { return SIMD_8x32::load_be(blocks[l] + 64 * n + off); };
      SIMD_8x32 W[16] = {load_w(0, 0),
                         load_w(1, 0),
                         load_w(2, 0),
                         load_w(3, 0),
                         load_w(4, 0),
                         load_w(5, 0),
                         load_w(6, 0),
                         load_w(7, 0),
                         load_w(0, 32),
                         load_w(1, 32),
                         load_w(2, 32),
                         load_w(3, 32),
                         load_w(4, 32),
                         load_w(5, 32),
                         load_w(6, 32),
                         load_w(7, 32)};
      SIMD_8x32::transpose(W[0], W[1], W[2], W[3], W[4], W[5], W[6], W[7]);
      SIMD_8x32::transpose(W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15]);

      SIMD_8x32 A = S[0];
      SIMD_8x32 B = S[1];
      SIMD_8x32 C = S[2];
      SIMD_8x32 D = S[3];
      SIMD_8x32 E = S[4];
      SIMD_8x32 F = S[5];
      SIMD_8x32 G = S[6];
      SIMD_8x32 H = S[7];

      for(size_t t = 0; t != 16; t += 8) {
         rnd(A, B, C, D, E, F, G, H, W[t + 0], SHA256_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, W[t + 1], SHA256_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, W[t + 2], SHA256_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, W[t + 3], SHA256_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, W[t + 4], SHA256_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, W[t + 5], SHA256_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, W[t + 6], SHA256_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, W[t + 7], SHA256_K[t + 7]);
      }

      for(size_t t = 16; t != 64; t += 8) {
         rnd(A, B, C, D, E, F, G, H, next_w(W, (t + 0) % 16), SHA256_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, next_w(W, (t + 1) % 16), SHA256_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, next_w(W, (t + 2) % 16), SHA256_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, next_w(W, (t + 3) % 16), SHA256_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, next_w(W, (t + 4) % 16), SHA256_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, next_w(W, (t + 5) % 16), SHA256_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, next_w(W, (t + 6) % 16), SHA256_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, next_w(W, (t + 7) % 16), SHA256_K[t + 7]);
      }

      S[0] += A;
      S[1] += B;
      S[2] += C;
      S[3] += D;
      S[4] += E;
      S[5] += F;
      S[6] += G;
      S[7] += H;
   }

   for(size_t j = 0; j != 8; ++j) {
      S[j].store_le(states + 32 * j);
   }
}

BOTAN_FN_ISA_AVX2 void sha2_32_mb_extract_x8(const uint8_t* states, uint8_t* digests) {
   SIMD_8x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_8x32::load_le(states + 32 * j);
   }

   // Each S[j] holds word j of all 8 lanes; the transpose turns that
   // into the 8 words of each lane
   SIMD_8x32::transpose(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7]);

   for(size_t l = 0; l != 8; ++l) {
      S[l].store_be(digests + 32 * l);
   }
}

}  // namespace Botan
