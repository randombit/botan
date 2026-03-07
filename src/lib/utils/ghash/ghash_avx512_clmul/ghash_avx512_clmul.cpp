/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ghash.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/polyval_fn.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/target_info.h>
#include <immintrin.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE __m512i BOTAN_FN_ISA_AVX512_CLMUL fold(__m512i H) {
   return _mm512_xor_si512(H, _mm512_bsrli_epi128(H, 8));
}

BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FN_ISA_AVX512_CLMUL reduce_xor(__m512i z) {
   auto y = _mm256_xor_si256(_mm512_castsi512_si256(z), _mm512_extracti64x4_epi64(z, 0x1));
   auto x = _mm_xor_si128(_mm256_castsi256_si128(y), _mm256_extracti32x4_epi32(y, 0x1));
   return SIMD_4x32(x);
}

BOTAN_FORCE_INLINE void BOTAN_FN_ISA_AVX512_CLMUL
ghash_x4_accum(__m512i H, __m512i H_fold, __m512i M, __m512i& lo, __m512i& hi, __m512i& mid) {
   lo = _mm512_xor_si512(lo, _mm512_clmulepi64_epi128(H, M, 0x00));
   hi = _mm512_xor_si512(hi, _mm512_clmulepi64_epi128(H, M, 0x11));
   mid = _mm512_xor_si512(mid, _mm512_clmulepi64_epi128(H_fold, fold(M), 0x00));
}

BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FN_ISA_AVX512_CLMUL ghash_reduce(__m512i lo, __m512i hi, __m512i mid) {
   mid = _mm512_ternarylogic_epi64(lo, mid, hi, 0x96);  // mid ^= lo ^ hi
   hi = _mm512_xor_si512(hi, _mm512_bsrli_epi128(mid, 8));
   lo = _mm512_xor_si512(lo, _mm512_bslli_epi128(mid, 8));
   return polyval_reduce(reduce_xor(hi), reduce_xor(lo));
}

BOTAN_FORCE_INLINE __m512i BOTAN_FN_ISA_AVX512_CLMUL insert_a(__m512i M, const SIMD_4x32& a) {
   return _mm512_xor_epi64(M, _mm512_inserti64x2(_mm512_setzero_si512(), a.raw(), 0));
}

}  // namespace

void BOTAN_FN_ISA_AVX512_CLMUL GHASH::ghash_precompute_avx512_clmul(const uint8_t H_bytes[16], uint64_t H_pow[16 * 2]) {
   const SIMD_4x32 H1 = mulx_polyval(reverse_vector(SIMD_4x32::load_le(H_bytes)));

   const SIMD_4x32 H2 = polyval_multiply(H1, H1);
   const SIMD_4x32 H3 = polyval_multiply(H1, H2);
   const SIMD_4x32 H4 = polyval_multiply(H2, H2);

   const SIMD_4x32 H5 = polyval_multiply(H4, H1);
   const SIMD_4x32 H6 = polyval_multiply(H4, H2);
   const SIMD_4x32 H7 = polyval_multiply(H4, H3);
   const SIMD_4x32 H8 = polyval_multiply(H4, H4);

   const SIMD_4x32 H9 = polyval_multiply(H8, H1);
   const SIMD_4x32 H10 = polyval_multiply(H8, H2);
   const SIMD_4x32 H11 = polyval_multiply(H8, H3);
   const SIMD_4x32 H12 = polyval_multiply(H8, H4);

   const SIMD_4x32 H13 = polyval_multiply(H8, H5);
   const SIMD_4x32 H14 = polyval_multiply(H8, H6);
   const SIMD_4x32 H15 = polyval_multiply(H8, H7);
   const SIMD_4x32 H16 = polyval_multiply(H8, H8);

   // Store in reversed order in blocks of 4 so that the zmm load
   // of H powers matches up with the message blocks
   H4.store_le(H_pow);
   H3.store_le(H_pow + 2);
   H2.store_le(H_pow + 4);
   H1.store_le(H_pow + 6);

   H8.store_le(H_pow + 8);
   H7.store_le(H_pow + 10);
   H6.store_le(H_pow + 12);
   H5.store_le(H_pow + 14);

   H12.store_le(H_pow + 16);
   H11.store_le(H_pow + 18);
   H10.store_le(H_pow + 20);
   H9.store_le(H_pow + 22);

   H16.store_le(H_pow + 24);
   H15.store_le(H_pow + 26);
   H14.store_le(H_pow + 28);
   H13.store_le(H_pow + 30);
}

void BOTAN_FN_ISA_AVX512_CLMUL GHASH::ghash_multiply_avx512_clmul(uint8_t x[16],
                                                                  const uint64_t H_pow[16 * 2],
                                                                  const uint8_t input[],
                                                                  size_t blocks) {
   SIMD_4x32 a = reverse_vector(SIMD_4x32::load_le(x));

   // Byte swap each lane
   const auto BSWAP = _mm512_set_epi64(0x0001020304050607,
                                       0x08090A0B0C0D0E0F,
                                       0x0001020304050607,
                                       0x08090A0B0C0D0E0F,
                                       0x0001020304050607,
                                       0x08090A0B0C0D0E0F,
                                       0x0001020304050607,
                                       0x08090A0B0C0D0E0F);

   if(blocks >= 16) {
      const auto H1 = _mm512_loadu_si512(H_pow);       // [H4,H3,H2,H1]
      const auto H2 = _mm512_loadu_si512(H_pow + 8);   // [H8,H7,H6,H5]
      const auto H3 = _mm512_loadu_si512(H_pow + 16);  // [H12,H11,H10,H9]
      const auto H4 = _mm512_loadu_si512(H_pow + 24);  // [H16,H15,H14,H13]

      // Precompute H folds (H ^ (H >> 64)) for Karatsuba - loop invariant
      const auto H1_fold = fold(H1);
      const auto H2_fold = fold(H2);
      const auto H3_fold = fold(H3);
      const auto H4_fold = fold(H4);

      while(blocks >= 16) {
         __m512i M1 = _mm512_shuffle_epi8(_mm512_loadu_si512(input), BSWAP);
         const auto M2 = _mm512_shuffle_epi8(_mm512_loadu_si512(input + 64), BSWAP);
         const auto M3 = _mm512_shuffle_epi8(_mm512_loadu_si512(input + 128), BSWAP);
         const auto M4 = _mm512_shuffle_epi8(_mm512_loadu_si512(input + 192), BSWAP);

         M1 = insert_a(M1, a);

         auto lo = _mm512_setzero_si512();
         auto hi = _mm512_setzero_si512();
         auto mid = _mm512_setzero_si512();

         ghash_x4_accum(H4, H4_fold, M1, lo, hi, mid);
         ghash_x4_accum(H3, H3_fold, M2, lo, hi, mid);
         ghash_x4_accum(H2, H2_fold, M3, lo, hi, mid);
         ghash_x4_accum(H1, H1_fold, M4, lo, hi, mid);

         a = ghash_reduce(lo, hi, mid);

         input += 16 * 16;
         blocks -= 16;
      }
   }

   if(blocks >= 8) {
      const auto H1 = _mm512_loadu_si512(H_pow);      // [H4,H3,H2,H1]
      const auto H2 = _mm512_loadu_si512(H_pow + 8);  // [H8,H7,H6,H5]

      const auto H1_fold = fold(H1);
      const auto H2_fold = fold(H2);

      while(blocks >= 8) {
         __m512i M1 = _mm512_shuffle_epi8(_mm512_loadu_si512(input), BSWAP);
         const __m512i M2 = _mm512_shuffle_epi8(_mm512_loadu_si512(input + 64), BSWAP);

         M1 = insert_a(M1, a);

         auto lo = _mm512_setzero_si512();
         auto hi = _mm512_setzero_si512();
         auto mid = _mm512_setzero_si512();

         ghash_x4_accum(H2, H2_fold, M1, lo, hi, mid);
         ghash_x4_accum(H1, H1_fold, M2, lo, hi, mid);

         a = ghash_reduce(lo, hi, mid);

         input += 8 * 16;
         blocks -= 8;
      }
   }

   if(blocks >= 4) {
      const auto H1 = _mm512_loadu_si512(H_pow);  // [H4,H3,H2,H1]
      const auto H1_fold = fold(H1);

      while(blocks >= 4) {
         __m512i M = _mm512_shuffle_epi8(_mm512_loadu_si512(input), BSWAP);
         M = insert_a(M, a);

         auto lo = _mm512_clmulepi64_epi128(H1, M, 0x00);
         auto hi = _mm512_clmulepi64_epi128(H1, M, 0x11);
         auto mid = _mm512_clmulepi64_epi128(H1_fold, fold(M), 0x00);

         a = ghash_reduce(lo, hi, mid);

         input += 4 * 16;
         blocks -= 4;
      }
   }

   if(blocks > 0) {
      // H1 is at offset 6 in the reversed layout [H4,H3,H2,H1,...]
      const SIMD_4x32 H1 = SIMD_4x32::load_le(H_pow + 6);

      for(size_t i = 0; i != blocks; ++i) {
         const SIMD_4x32 m = reverse_vector(SIMD_4x32::load_le(input + 16 * i));
         a ^= m;
         a = polyval_multiply(H1, a);
      }
   }

   a = reverse_vector(a);
   a.store_le(x);
}

}  // namespace Botan
