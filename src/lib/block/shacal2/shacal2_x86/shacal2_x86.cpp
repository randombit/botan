/*
* SHACAL-2 using x86 SHA extensions
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/shacal2.h>
#include <immintrin.h>

namespace Botan {

/*
Only encryption is supported since the inverse round function would
require a different instruction
*/

void SHACAL2::x86_encrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   // TODO x4 unrolling

   const __m128i BSWAP_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0B, 0x0405060700010203);

   const __m128i* in_mm = reinterpret_cast<const __m128i*>(in);
   __m128i* out_mm = reinterpret_cast<__m128i*>(out);

   while(blocks)
      {
      __m128i B0 = _mm_loadu_si128(in_mm);
      __m128i B1 = _mm_loadu_si128(in_mm+1);

      B0 = _mm_shuffle_epi8(B0, BSWAP_MASK);
      B1 = _mm_shuffle_epi8(B1, BSWAP_MASK);

      B0 = _mm_shuffle_epi32(B0, 0xB1); // CDAB
      B1 = _mm_shuffle_epi32(B1, 0x1B); // EFGH

      __m128i TMP  = _mm_alignr_epi8(B0, B1, 8); // ABEF
      B1 = _mm_blend_epi16(B1, B0, 0xF0); // CDGH
      B0 = TMP;

      for(size_t i = 0; i != 8; ++i)
         {
         B1 = _mm_sha256rnds2_epu32(B1, B0, _mm_set_epi32(0,0,m_RK[8*i+1],m_RK[8*i+0]));
         B0 = _mm_sha256rnds2_epu32(B0, B1, _mm_set_epi32(0,0,m_RK[8*i+3],m_RK[8*i+2]));
         B1 = _mm_sha256rnds2_epu32(B1, B0, _mm_set_epi32(0,0,m_RK[8*i+5],m_RK[8*i+4]));
         B0 = _mm_sha256rnds2_epu32(B0, B1, _mm_set_epi32(0,0,m_RK[8*i+7],m_RK[8*i+6]));
         }

      TMP = _mm_shuffle_epi32(B0, 0x1B); // FEBA
      B1 = _mm_shuffle_epi32(B1, 0xB1); // DCHG
      B0 = _mm_blend_epi16(TMP, B1, 0xF0); // DCBA
      B1 = _mm_alignr_epi8(B1, TMP, 8); // ABEF

      B0 = _mm_shuffle_epi8(B0, BSWAP_MASK);
      B1 = _mm_shuffle_epi8(B1, BSWAP_MASK);

      // Save state
      _mm_storeu_si128(out_mm, B0);
      _mm_storeu_si128(out_mm + 1, B1);

      blocks--;
      in_mm += 2;
      out_mm += 2;
      }
   }

}
