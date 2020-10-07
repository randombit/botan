/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ghash.h>
#include <immintrin.h>

namespace Botan {

// TODO: extend this to support NEON and AltiVec

BOTAN_FUNC_ISA("ssse3")
void GHASH::ghash_multiply_vperm(uint8_t x[16],
                                 const uint64_t HM[256],
                                 const uint8_t input_bytes[], size_t blocks)
   {
   const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

   const __m128i* HM_mm = reinterpret_cast<const __m128i*>(HM);

   __m128i X = _mm_loadu_si128(reinterpret_cast<__m128i*>(x));
   X = _mm_shuffle_epi8(X, BSWAP_MASK);

   const __m128i ones = _mm_set1_epi8(-1);

   for(size_t b = 0; b != blocks; ++b)
      {
      __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input_bytes) + b);
      M = _mm_shuffle_epi8(M, BSWAP_MASK);

      X = _mm_xor_si128(X, M);

      __m128i Z = _mm_setzero_si128();

      for(size_t i = 0; i != 64; i += 2)
         {
         const __m128i HM0 = _mm_loadu_si128(HM_mm + 2*i);
         const __m128i HM1 = _mm_loadu_si128(HM_mm + 2*i + 1);
         const __m128i HM2 = _mm_loadu_si128(HM_mm + 2*i + 2);
         const __m128i HM3 = _mm_loadu_si128(HM_mm + 2*i + 3);

         const __m128i XMASK1 = _mm_add_epi64(_mm_srli_epi64(X, 63), ones);
         X = _mm_slli_epi64(X, 1);
         const __m128i XMASK2 = _mm_add_epi64(_mm_srli_epi64(X, 63), ones);
         X = _mm_slli_epi64(X, 1);

         Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpackhi_epi64(XMASK1, XMASK1), HM0));
         Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpacklo_epi64(XMASK1, XMASK1), HM1));
         Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpackhi_epi64(XMASK2, XMASK2), HM2));
         Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpacklo_epi64(XMASK2, XMASK2), HM3));
         }

      X = _mm_shuffle_epi32(Z, _MM_SHUFFLE(1, 0, 3, 2));
      }

   X = _mm_shuffle_epi8(X, BSWAP_MASK);
   _mm_storeu_si128(reinterpret_cast<__m128i*>(x), X);
   }

}
