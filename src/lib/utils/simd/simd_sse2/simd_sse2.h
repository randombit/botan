/*
* Lightweight wrappers for SSE2 intrinsics for 32-bit operations
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_SSE_H__
#define BOTAN_SIMD_SSE_H__

#if defined(BOTAN_TARGET_SUPPORTS_SSE2)

#include <botan/cpuid.h>
#include <emmintrin.h>

namespace Botan {

class SIMD_SSE2
   {
   public:
      explicit SIMD_SSE2(const u32bit B[4])
         {
         m_reg = _mm_loadu_si128(reinterpret_cast<const __m128i*>(B));
         }

      SIMD_SSE2(u32bit B0, u32bit B1, u32bit B2, u32bit B3)
         {
         m_reg = _mm_set_epi32(B0, B1, B2, B3);
         }

      explicit SIMD_SSE2(u32bit B)
         {
         m_reg = _mm_set1_epi32(B);
         }

      static SIMD_SSE2 load_le(const void* in)
         {
         return SIMD_SSE2(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
         }

      static SIMD_SSE2 load_be(const void* in)
         {
         return load_le(in).bswap();
         }

      void store_le(byte out[]) const
         {
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_reg);
         }

      void store_be(byte out[]) const
         {
         bswap().store_le(out);
         }

      void rotate_left(size_t rot)
         {
         m_reg = _mm_or_si128(_mm_slli_epi32(m_reg, static_cast<int>(rot)),
                            _mm_srli_epi32(m_reg, static_cast<int>(32-rot)));
         }

      void rotate_right(size_t rot)
         {
         rotate_left(32 - rot);
         }

      void operator+=(const SIMD_SSE2& other)
         {
         m_reg = _mm_add_epi32(m_reg, other.m_reg);
         }

      SIMD_SSE2 operator+(const SIMD_SSE2& other) const
         {
         return SIMD_SSE2(_mm_add_epi32(m_reg, other.m_reg));
         }

      void operator-=(const SIMD_SSE2& other)
         {
         m_reg = _mm_sub_epi32(m_reg, other.m_reg);
         }

      SIMD_SSE2 operator-(const SIMD_SSE2& other) const
         {
         return SIMD_SSE2(_mm_sub_epi32(m_reg, other.m_reg));
         }

      void operator^=(const SIMD_SSE2& other)
         {
         m_reg = _mm_xor_si128(m_reg, other.m_reg);
         }

      SIMD_SSE2 operator^(const SIMD_SSE2& other) const
         {
         return SIMD_SSE2(_mm_xor_si128(m_reg, other.m_reg));
         }

      void operator|=(const SIMD_SSE2& other)
         {
         m_reg = _mm_or_si128(m_reg, other.m_reg);
         }

      SIMD_SSE2 operator&(const SIMD_SSE2& other)
         {
         return SIMD_SSE2(_mm_and_si128(m_reg, other.m_reg));
         }

      void operator&=(const SIMD_SSE2& other)
         {
         m_reg = _mm_and_si128(m_reg, other.m_reg);
         }

      SIMD_SSE2 operator<<(size_t shift) const
         {
         return SIMD_SSE2(_mm_slli_epi32(m_reg, static_cast<int>(shift)));
         }

      SIMD_SSE2 operator>>(size_t shift) const
         {
         return SIMD_SSE2(_mm_srli_epi32(m_reg, static_cast<int>(shift)));
         }

      SIMD_SSE2 operator~() const
         {
         return SIMD_SSE2(_mm_xor_si128(m_reg, _mm_set1_epi32(0xFFFFFFFF)));
         }

      // (~reg) & other
      SIMD_SSE2 andc(const SIMD_SSE2& other)
         {
         return SIMD_SSE2(_mm_andnot_si128(m_reg, other.m_reg));
         }

      SIMD_SSE2 bswap() const
         {
         __m128i T = m_reg;

         T = _mm_shufflehi_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));
         T = _mm_shufflelo_epi16(T, _MM_SHUFFLE(2, 3, 0, 1));

         return SIMD_SSE2(_mm_or_si128(_mm_srli_epi16(T, 8),
                             _mm_slli_epi16(T, 8)));
         }

      static void transpose(SIMD_SSE2& B0, SIMD_SSE2& B1,
                            SIMD_SSE2& B2, SIMD_SSE2& B3)
         {
         __m128i T0 = _mm_unpacklo_epi32(B0.m_reg, B1.m_reg);
         __m128i T1 = _mm_unpacklo_epi32(B2.m_reg, B3.m_reg);
         __m128i T2 = _mm_unpackhi_epi32(B0.m_reg, B1.m_reg);
         __m128i T3 = _mm_unpackhi_epi32(B2.m_reg, B3.m_reg);
         B0.m_reg = _mm_unpacklo_epi64(T0, T1);
         B1.m_reg = _mm_unpackhi_epi64(T0, T1);
         B2.m_reg = _mm_unpacklo_epi64(T2, T3);
         B3.m_reg = _mm_unpackhi_epi64(T2, T3);
         }

   private:
      explicit SIMD_SSE2(__m128i in) { m_reg = in; }

      __m128i m_reg;
   };

}

#endif

#endif
