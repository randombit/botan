/**
* (C) 2022,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_2X64_H_
#define BOTAN_SIMD_2X64_H_

#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
   #include <tmmintrin.h>
   #define BOTAN_SIMD_2X64_ISA_FUNC BOTAN_FUNC_ISA("ssse3")
#endif

#if defined(BOTAN_TARGET_SUPPORTS_NEON)
   #include <arm_neon.h>
   #define BOTAN_SIMD_2X64_ISA_FUNC /**/
#endif

#include <botan/internal/cpuid.h>

namespace Botan {

class SIMD_2x64 final {
   public:
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
      using native_simd_type = __m128i;
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
      using native_simd_type = uint64x2_t;
#endif

      SIMD_2x64& operator=(const SIMD_2x64& other) = default;
      SIMD_2x64(const SIMD_2x64& other) = default;

      SIMD_2x64& operator=(SIMD_2x64&& other) = default;
      SIMD_2x64(SIMD_2x64&& other) = default;

      ~SIMD_2x64() = default;

      // zero initialized
      SIMD_2x64() {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         m_simd = _mm_setzero_si128();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         m_simd = vdupq_n_u64(0);
#endif
      }

      static SIMD_2x64 load_le(const void* in) {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         return SIMD_2x64(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         return SIMD_2x64(vld1q_u64(static_cast<const uint64_t*>(in)));
#endif
      }

      void store_le(uint64_t out[2]) const { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      void store_le(uint8_t out[]) const {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_simd);
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         vst1q_u8(out, vreinterpretq_u8_u64(m_simd));
#endif
      }

      SIMD_2x64 operator+(const SIMD_2x64& other) const {
         SIMD_2x64 retval(*this);
         retval += other;
         return retval;
      }

      SIMD_2x64 operator^(const SIMD_2x64& other) const {
         SIMD_2x64 retval(*this);
         retval ^= other;
         return retval;
      }

      void operator+=(const SIMD_2x64& other) {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         m_simd = _mm_add_epi64(m_simd, other.m_simd);
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         m_simd = vaddq_u64(m_simd, other.m_simd);
#endif
      }

      void operator^=(const SIMD_2x64& other) {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         m_simd = _mm_xor_si128(m_simd, other.m_simd);
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         m_simd = veorq_u64(m_simd, other.m_simd);
#endif
      }

      template <size_t ROT>
      BOTAN_SIMD_2X64_ISA_FUNC SIMD_2x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         if constexpr(ROT == 16) {
            auto tab = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 24) {
            auto tab = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 32) {
            return SIMD_2x64(_mm_shuffle_epi32(m_simd, 0b10110001));
         } else {
            return SIMD_2x64(_mm_or_si128(_mm_srli_epi64(m_simd, static_cast<int>(ROT)),
                                          _mm_slli_epi64(m_simd, static_cast<int>(64 - ROT))));
         }
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         return SIMD_2x64(
            vorrq_u64(vshrq_n_u64(m_simd, static_cast<int>(ROT)), vshlq_n_u64(m_simd, static_cast<int>(64 - ROT))));
#endif
      }

      // Argon2 specific operation
      static SIMD_2x64 mul2_32(SIMD_2x64 x, SIMD_2x64 y) {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         const __m128i m = _mm_mul_epu32(x.m_simd, y.m_simd);
         return SIMD_2x64(_mm_add_epi64(m, m));
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         uint32x2_t a_lo = vmovn_u64(x.m_simd);
         uint32x2_t b_lo = vmovn_u64(y.m_simd);
         const uint64x2_t m = vmull_u32(a_lo, b_lo);
         return SIMD_2x64(vaddq_u64(m, m));
#endif
      }

      static BOTAN_SIMD_2X64_ISA_FUNC SIMD_2x64 alignr8(SIMD_2x64 a, SIMD_2x64 b) {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         return SIMD_2x64(_mm_alignr_epi8(a.m_simd, b.m_simd, 8));
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         const uint8x16_t t = vextq_u8(vreinterpretq_u8_u64(b.m_simd), vreinterpretq_u8_u64(a.m_simd), 8);
         return SIMD_2x64(vreinterpretq_u64_u8(t));
#endif
      }

      // Argon2 specific
      static void twist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         SIMD_2x64 T0;

         T0 = SIMD_2x64::alignr8(B1, B0);
         B1 = SIMD_2x64::alignr8(B0, B1);
         B0 = T0;

         T0 = C0;
         C0 = C1;
         C1 = T0;

         T0 = SIMD_2x64::alignr8(D0, D1);
         D1 = SIMD_2x64::alignr8(D1, D0);
         D0 = T0;
      }

      // Argon2 specific
      static void untwist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         SIMD_2x64 T0, T1;

         T0 = SIMD_2x64::alignr8(B0, B1);
         B1 = SIMD_2x64::alignr8(B1, B0);
         B0 = T0;

         T0 = C0;
         C0 = C1;
         C1 = T0;

         T0 = SIMD_2x64::alignr8(D1, D0);
         D1 = SIMD_2x64::alignr8(D0, D1);
         D0 = T0;
      }

      explicit SIMD_2x64(native_simd_type x) : m_simd(x) {}

   private:
      native_simd_type m_simd;
};

}  // namespace Botan

#endif
