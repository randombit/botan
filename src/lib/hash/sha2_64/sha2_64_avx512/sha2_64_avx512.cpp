/*
* (C) 2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/simd_2x64.h>
#include <botan/internal/simd_8x64.h>

namespace Botan {

namespace SHA512_AVX512 {

namespace {

template <size_t R1, size_t R2, size_t S1>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_BMI2 SIMD_2x64 avx512_sigma(SIMD_2x64 v) {
   const auto vr1 = _mm_ror_epi64(v.raw(), R1);
   const auto vr2 = _mm_ror_epi64(v.raw(), R2);
   const auto vs1 = _mm_srli_epi64(v.raw(), S1);
   return SIMD_2x64(_mm_ternarylogic_epi64(vr1, vr2, vs1, 0x96));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_BMI2 SIMD_2x64 sha512_next_w_avx512(SIMD_2x64 x[8]) {
   auto t0 = SIMD_2x64::alignr8(x[1], x[0]);
   auto t1 = SIMD_2x64::alignr8(x[5], x[4]);

   auto s0 = avx512_sigma<1, 8, 7>(t0);
   auto s1 = avx512_sigma<19, 61, 6>(x[7]);

   auto nx = x[0] + s0 + s1 + t1;

   x[0] = x[1];
   x[1] = x[2];
   x[2] = x[3];
   x[3] = x[4];
   x[4] = x[5];
   x[5] = x[6];
   x[6] = x[7];
   x[7] = nx;

   return nx;
}

template <size_t R1, size_t R2, size_t R3>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_BMI2 SIMD_2x64 rho(SIMD_2x64 v) {
   const auto vr1 = _mm_ror_epi64(v.raw(), R1);
   const auto vr2 = _mm_ror_epi64(v.raw(), R2);
   const auto vr3 = _mm_ror_epi64(v.raw(), R3);
   return SIMD_2x64(_mm_ternarylogic_epi64(vr1, vr2, vr3, 0x96));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX512_BMI2 void SHA2_64_F(SIMD_2x64 A,
                                                           SIMD_2x64 B,
                                                           SIMD_2x64 C,
                                                           SIMD_2x64& D,
                                                           SIMD_2x64 E,
                                                           SIMD_2x64 F,
                                                           SIMD_2x64 G,
                                                           SIMD_2x64& H,
                                                           uint64_t M) {
   constexpr uint8_t ch = 0xca;
   constexpr uint8_t maj = 0xe8;

   H += rho<14, 18, 41>(E) + SIMD_2x64(_mm_ternarylogic_epi64(E.raw(), F.raw(), G.raw(), ch)) + SIMD_2x64::splat(M);
   D += H;
   H += rho<28, 34, 39>(A) + SIMD_2x64(_mm_ternarylogic_epi64(A.raw(), B.raw(), C.raw(), maj));
}

}  // namespace

}  // namespace SHA512_AVX512

BOTAN_FN_ISA_AVX512_BMI2 void SHA_512::compress_digest_x86_avx512(digest_type& digest,
                                                                  std::span<const uint8_t> input,
                                                                  size_t blocks) {
   using namespace SHA512_AVX512;

   alignas(64) uint64_t W[16] = {0};

   auto digest0 = SIMD_2x64::splat(digest[0]);
   auto digest1 = SIMD_2x64::splat(digest[1]);
   auto digest2 = SIMD_2x64::splat(digest[2]);
   auto digest3 = SIMD_2x64::splat(digest[3]);
   auto digest4 = SIMD_2x64::splat(digest[4]);
   auto digest5 = SIMD_2x64::splat(digest[5]);
   auto digest6 = SIMD_2x64::splat(digest[6]);
   auto digest7 = SIMD_2x64::splat(digest[7]);

   auto A = digest0;
   auto B = digest1;
   auto C = digest2;
   auto D = digest3;
   auto E = digest4;
   auto F = digest5;
   auto G = digest6;
   auto H = digest7;

   const uint8_t* data = input.data();

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
         auto w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 16]);
         SHA2_64_F(A, B, C, D, E, F, G, H, W[0]);
         SHA2_64_F(H, A, B, C, D, E, F, G, W[1]);
         w.store_le(&W[0]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 18]);
         SHA2_64_F(G, H, A, B, C, D, E, F, W[2]);
         SHA2_64_F(F, G, H, A, B, C, D, E, W[3]);
         w.store_le(&W[2]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 20]);
         SHA2_64_F(E, F, G, H, A, B, C, D, W[4]);
         SHA2_64_F(D, E, F, G, H, A, B, C, W[5]);
         w.store_le(&W[4]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 22]);
         SHA2_64_F(C, D, E, F, G, H, A, B, W[6]);
         SHA2_64_F(B, C, D, E, F, G, H, A, W[7]);
         w.store_le(&W[6]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 24]);
         SHA2_64_F(A, B, C, D, E, F, G, H, W[8]);
         SHA2_64_F(H, A, B, C, D, E, F, G, W[9]);
         w.store_le(&W[8]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 26]);
         SHA2_64_F(G, H, A, B, C, D, E, F, W[10]);
         SHA2_64_F(F, G, H, A, B, C, D, E, W[11]);
         w.store_le(&W[10]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 28]);
         SHA2_64_F(E, F, G, H, A, B, C, D, W[12]);
         SHA2_64_F(D, E, F, G, H, A, B, C, W[13]);
         w.store_le(&W[12]);

         w = sha512_next_w_avx512(WS) + SIMD_2x64::load_le(&SHA512_K[r + 30]);
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

      digest0 += A;
      digest1 += B;
      digest2 += C;
      digest3 += D;
      digest4 += E;
      digest5 += F;
      digest6 += G;
      digest7 += H;

      A = digest0;
      B = digest1;
      C = digest2;
      D = digest3;
      E = digest4;
      F = digest5;
      G = digest6;
      H = digest7;
   }

   // Could be optimized a bit by interleaving the registers, reducing store pressure
   // but probably not worth bothering with
   _mm_mask_storeu_epi64(&digest[0], 0b01, digest0.raw());  // NOLINT(*-container-data-pointer)
   _mm_mask_storeu_epi64(&digest[1], 0b01, digest1.raw());
   _mm_mask_storeu_epi64(&digest[2], 0b01, digest2.raw());
   _mm_mask_storeu_epi64(&digest[3], 0b01, digest3.raw());
   _mm_mask_storeu_epi64(&digest[4], 0b01, digest4.raw());
   _mm_mask_storeu_epi64(&digest[5], 0b01, digest5.raw());
   _mm_mask_storeu_epi64(&digest[6], 0b01, digest6.raw());
   _mm_mask_storeu_epi64(&digest[7], 0b01, digest7.raw());
}

}  // namespace Botan
