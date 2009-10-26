/**
* Lightweight wrappers for SSE2 intrinsics for 32-bit operations
*/

#ifndef BOTAN_SIMD_SSE_H__
#define BOTAN_SIMD_SSE_H__

#include <botan/types.h>
#include <emmintrin.h>

namespace Botan {

class SIMD_SSE2
   {
   public:
      SIMD_SSE2(const u32bit B[4])
         {
         reg = _mm_loadu_si128((const __m128i*)B);
         }

      SIMD_SSE2(u32bit B0, u32bit B1, u32bit B2, u32bit B3)
         {
         reg = _mm_set_epi32(B0, B1, B2, B3);
         }

      SIMD_SSE2(u32bit B)
         {
         reg = _mm_set1_epi32(B);
         }

      static SIMD_SSE2 load_le(const void* in)
         {
         return _mm_loadu_si128((const __m128i*)in);
         }

      static SIMD_SSE2 load_be(const void* in)
         {
         return SIMD_SSE2(_mm_loadu_si128((const __m128i*)in)).bswap();
         }

      void store_le(byte out[]) const
         {
         _mm_storeu_si128((__m128i*)out, reg);
         }

      void store_be(byte out[]) const
         {
         bswap().store_le(out);
         }

      void rotate_left(u32bit rot)
         {
         reg = _mm_or_si128(_mm_slli_epi32(reg, rot),
                            _mm_srli_epi32(reg, 32-rot));
         }

      void rotate_right(u32bit rot)
         {
         reg = _mm_or_si128(_mm_srli_epi32(reg, rot),
                            _mm_slli_epi32(reg, 32-rot));
         }

      void operator+=(const SIMD_SSE2& other)
         {
         reg = _mm_add_epi32(reg, other.reg);
         }

      SIMD_SSE2 operator+(const SIMD_SSE2& other) const
         {
         return _mm_add_epi32(reg, other.reg);
         }

      void operator-=(const SIMD_SSE2& other)
         {
         reg = _mm_sub_epi32(reg, other.reg);
         }

      SIMD_SSE2 operator-(const SIMD_SSE2& other) const
         {
         return _mm_sub_epi32(reg, other.reg);
         }

      void operator^=(const SIMD_SSE2& other)
         {
         reg = _mm_xor_si128(reg, other.reg);
         }

      SIMD_SSE2 operator^(const SIMD_SSE2& other) const
         {
         return _mm_xor_si128(reg, other.reg);
         }

      void operator|=(const SIMD_SSE2& other)
         {
         reg = _mm_or_si128(reg, other.reg);
         }

      void operator&=(const SIMD_SSE2& other)
         {
         reg = _mm_and_si128(reg, other.reg);
         }

      SIMD_SSE2 operator<<(u32bit shift) const
         {
         return _mm_slli_epi32(reg, shift);
         }

      SIMD_SSE2 operator>>(u32bit shift) const
         {
         return _mm_srli_epi32(reg, shift);
         }

      SIMD_SSE2 operator~() const
         {
         static const __m128i all_ones = _mm_set1_epi32(0xFFFFFFFF);
         return _mm_xor_si128(reg, all_ones);
         }

      static void transpose(SIMD_SSE2& B0, SIMD_SSE2& B1,
                            SIMD_SSE2& B2, SIMD_SSE2& B3)
         {
         __m128i T0 = _mm_unpacklo_epi32(B0.reg, B1.reg);
         __m128i T1 = _mm_unpacklo_epi32(B2.reg, B3.reg);
         __m128i T2 = _mm_unpackhi_epi32(B0.reg, B1.reg);
         __m128i T3 = _mm_unpackhi_epi32(B2.reg, B3.reg);
         B0.reg = _mm_unpacklo_epi64(T0, T1);
         B1.reg = _mm_unpackhi_epi64(T0, T1);
         B2.reg = _mm_unpacklo_epi64(T2, T3);
         B3.reg = _mm_unpackhi_epi64(T2, T3);
         }

   private:
      SIMD_SSE2(__m128i in) { reg = in; }

      SIMD_SSE2 bswap() const
         {
         __m128i T = reg;

         T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
         T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

         return _mm_or_si128(_mm_srli_epi16(T, 8),
                             _mm_slli_epi16(T, 8));
         }

      __m128i reg;
   };

}

#endif
