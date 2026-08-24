/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_avx512.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_AVX512 BOTAN_FORCE_INLINE void rnd(const SIMD_16x32& A,
                                                const SIMD_16x32& B,
                                                const SIMD_16x32& C,
                                                SIMD_16x32& D,
                                                const SIMD_16x32& E,
                                                const SIMD_16x32& F,
                                                const SIMD_16x32& G,
                                                SIMD_16x32& H,
                                                const SIMD_16x32& W,
                                                uint32_t K) {
   const auto T1 = H + E.sigma1() + SIMD_16x32::choose(E, F, G) + SIMD_16x32::splat(K) + W;
   const auto T2 = A.sigma0() + SIMD_16x32::majority(A, B, C);
   D += T1;
   H = T1 + T2;
}

template <size_t I>
BOTAN_FN_ISA_AVX512 BOTAN_FORCE_INLINE SIMD_16x32 next_w(SIMD_16x32 W[16]) {
   const auto& w15 = W[(I + 1) % 16];
   const auto& w2 = W[(I + 14) % 16];
   const auto s0 = w15.rotr<7>() ^ w15.rotr<18>() ^ w15.shr<3>();
   const auto s1 = w2.rotr<17>() ^ w2.rotr<19>() ^ w2.shr<10>();
   W[I] += s0 + s1 + W[(I + 9) % 16];
   return W[I];
}

/**
* Store each 128-bit quarter of v separately, quarter q to out + q * stride
*/
BOTAN_FN_ISA_AVX512 BOTAN_FORCE_INLINE void store_quarters(const SIMD_16x32& v, uint8_t* out, size_t stride) {
   _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm512_castsi512_si128(v.raw()));
   _mm_storeu_si128(reinterpret_cast<__m128i*>(out + stride), _mm512_extracti32x4_epi32(v.raw(), 1));
   _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 2 * stride), _mm512_extracti32x4_epi32(v.raw(), 2));
   _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 3 * stride), _mm512_extracti32x4_epi32(v.raw(), 3));
}

}  // namespace

BOTAN_FN_ISA_AVX512 void sha2_32_mb_compress_x16(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   alignas(64) const uint32_t SHA256_K[64] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};
   SIMD_16x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_16x32::load_le(states + 64 * j);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // Initialized directly from the loads, since default construction
      // would zero the whole array first
      auto load_w = [&](size_t l) { return SIMD_16x32::load_be(blocks[l] + 64 * n); };
      SIMD_16x32 W[16] = {load_w(0),
                          load_w(1),
                          load_w(2),
                          load_w(3),
                          load_w(4),
                          load_w(5),
                          load_w(6),
                          load_w(7),
                          load_w(8),
                          load_w(9),
                          load_w(10),
                          load_w(11),
                          load_w(12),
                          load_w(13),
                          load_w(14),
                          load_w(15)};
      SIMD_16x32::transpose(
         W[0], W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15]);

      SIMD_16x32 A = S[0];
      SIMD_16x32 B = S[1];
      SIMD_16x32 C = S[2];
      SIMD_16x32 D = S[3];
      SIMD_16x32 E = S[4];
      SIMD_16x32 F = S[5];
      SIMD_16x32 G = S[6];
      SIMD_16x32 H = S[7];

      // Every index into W is a constant so that it can stay in registers
      rnd(A, B, C, D, E, F, G, H, W[0], SHA256_K[0]);
      rnd(H, A, B, C, D, E, F, G, W[1], SHA256_K[1]);
      rnd(G, H, A, B, C, D, E, F, W[2], SHA256_K[2]);
      rnd(F, G, H, A, B, C, D, E, W[3], SHA256_K[3]);
      rnd(E, F, G, H, A, B, C, D, W[4], SHA256_K[4]);
      rnd(D, E, F, G, H, A, B, C, W[5], SHA256_K[5]);
      rnd(C, D, E, F, G, H, A, B, W[6], SHA256_K[6]);
      rnd(B, C, D, E, F, G, H, A, W[7], SHA256_K[7]);
      rnd(A, B, C, D, E, F, G, H, W[8], SHA256_K[8]);
      rnd(H, A, B, C, D, E, F, G, W[9], SHA256_K[9]);
      rnd(G, H, A, B, C, D, E, F, W[10], SHA256_K[10]);
      rnd(F, G, H, A, B, C, D, E, W[11], SHA256_K[11]);
      rnd(E, F, G, H, A, B, C, D, W[12], SHA256_K[12]);
      rnd(D, E, F, G, H, A, B, C, W[13], SHA256_K[13]);
      rnd(C, D, E, F, G, H, A, B, W[14], SHA256_K[14]);
      rnd(B, C, D, E, F, G, H, A, W[15], SHA256_K[15]);

      for(size_t t = 16; t != 64; t += 16) {
         rnd(A, B, C, D, E, F, G, H, next_w<0>(W), SHA256_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, next_w<1>(W), SHA256_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, next_w<2>(W), SHA256_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, next_w<3>(W), SHA256_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, next_w<4>(W), SHA256_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, next_w<5>(W), SHA256_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, next_w<6>(W), SHA256_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, next_w<7>(W), SHA256_K[t + 7]);
         rnd(A, B, C, D, E, F, G, H, next_w<8>(W), SHA256_K[t + 8]);
         rnd(H, A, B, C, D, E, F, G, next_w<9>(W), SHA256_K[t + 9]);
         rnd(G, H, A, B, C, D, E, F, next_w<10>(W), SHA256_K[t + 10]);
         rnd(F, G, H, A, B, C, D, E, next_w<11>(W), SHA256_K[t + 11]);
         rnd(E, F, G, H, A, B, C, D, next_w<12>(W), SHA256_K[t + 12]);
         rnd(D, E, F, G, H, A, B, C, next_w<13>(W), SHA256_K[t + 13]);
         rnd(C, D, E, F, G, H, A, B, next_w<14>(W), SHA256_K[t + 14]);
         rnd(B, C, D, E, F, G, H, A, next_w<15>(W), SHA256_K[t + 15]);
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
      S[j].store_le(states + 64 * j);
   }
}

BOTAN_FN_ISA_AVX512 void sha2_32_mb_extract_x16(const uint8_t* states, uint8_t* digests) {
   SIMD_16x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_16x32::load_le(states + 64 * j).bswap();
   }

   // Each S[j] holds word j of all 16 lanes. The 4-way transpose works
   // within each 128-bit quarter, so afterwards quarter q of S[k] holds
   // words 0..3 of lane 4*q+k, and quarter q of S[4+k] its words 4..7.
   SIMD_16x32::transpose(S[0], S[1], S[2], S[3]);
   SIMD_16x32::transpose(S[4], S[5], S[6], S[7]);

   for(size_t k = 0; k != 4; ++k) {
      store_quarters(S[k], digests + 32 * k, 128);
      store_quarters(S[4 + k], digests + 32 * k + 16, 128);
   }
}

}  // namespace Botan
