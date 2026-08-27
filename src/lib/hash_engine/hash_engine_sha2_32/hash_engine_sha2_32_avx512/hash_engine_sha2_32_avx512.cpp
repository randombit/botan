/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_32_f.h>
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
   SIMD_16x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_16x32::load_le(states + 64 * j);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // Initialized directly from the loads, since default construction
      // would zero the whole array first
      SIMD_16x32 W[16] = {SIMD_16x32::load_be<64>(blocks, 0, n),
                          SIMD_16x32::load_be<64>(blocks, 1, n),
                          SIMD_16x32::load_be<64>(blocks, 2, n),
                          SIMD_16x32::load_be<64>(blocks, 3, n),
                          SIMD_16x32::load_be<64>(blocks, 4, n),
                          SIMD_16x32::load_be<64>(blocks, 5, n),
                          SIMD_16x32::load_be<64>(blocks, 6, n),
                          SIMD_16x32::load_be<64>(blocks, 7, n),
                          SIMD_16x32::load_be<64>(blocks, 8, n),
                          SIMD_16x32::load_be<64>(blocks, 9, n),
                          SIMD_16x32::load_be<64>(blocks, 10, n),
                          SIMD_16x32::load_be<64>(blocks, 11, n),
                          SIMD_16x32::load_be<64>(blocks, 12, n),
                          SIMD_16x32::load_be<64>(blocks, 13, n),
                          SIMD_16x32::load_be<64>(blocks, 14, n),
                          SIMD_16x32::load_be<64>(blocks, 15, n)};
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
