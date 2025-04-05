/*
* (C) 2022,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_2X64_H_
#define BOTAN_SIMD_2X64_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <botan/internal/target_info.h>

#if defined(BOTAN_TARGET_CPU_SUPPORTS_SSSE3)
   #include <emmintrin.h>
   #include <tmmintrin.h>
   #define BOTAN_SIMD_USE_SSSE3
   #define BOTAN_SIMD_2X64_ISA "ssse3"
   #define BOTAN_SIMD_2X64_FN BOTAN_FUNC_ISA(BOTAN_SIMD_2X64_ISA)
#endif

namespace Botan {

class SIMD_2x64 final {
   public:
      SIMD_2x64& operator=(const SIMD_2x64& other) = default;
      SIMD_2x64(const SIMD_2x64& other) = default;

      SIMD_2x64& operator=(SIMD_2x64&& other) = default;
      SIMD_2x64(SIMD_2x64&& other) = default;

      ~SIMD_2x64() = default;

      // zero initialized
      SIMD_2x64() { m_simd = _mm_setzero_si128(); }

      static SIMD_2x64 load_le(const void* in) {
         return SIMD_2x64(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
      }

      static SIMD_2x64 load_be(const void* in) { return SIMD_2x64::load_le(in).bswap(); }

      SIMD_2x64 BOTAN_SIMD_2X64_FN bswap() const {
         const auto idx = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
         return SIMD_2x64(_mm_shuffle_epi8(m_simd, idx));
      }

      void store_le(uint64_t out[2]) const { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      void store_le(uint8_t out[]) const { _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_simd); }

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

      void operator+=(const SIMD_2x64& other) { m_simd = _mm_add_epi64(m_simd, other.m_simd); }

      void operator^=(const SIMD_2x64& other) { m_simd = _mm_xor_si128(m_simd, other.m_simd); }

      template <size_t ROT>
      BOTAN_SIMD_2X64_FN SIMD_2x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
         if constexpr(ROT == 8) {
            auto tab = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 16) {
            auto tab = _mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 24) {
            auto tab = _mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else if constexpr(ROT == 32) {
            auto tab = _mm_setr_epi8(4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11);
            return SIMD_2x64(_mm_shuffle_epi8(m_simd, tab));
         } else {
            return SIMD_2x64(_mm_or_si128(_mm_srli_epi64(m_simd, static_cast<int>(ROT)),
                                          _mm_slli_epi64(m_simd, static_cast<int>(64 - ROT))));
         }
      }

      template <size_t ROT>
      SIMD_2x64 rotl() const {
         return this->rotr<64 - ROT>();
      }

      template <int SHIFT>
      SIMD_2x64 shr() const noexcept {
         return SIMD_2x64(_mm_srli_epi64(m_simd, SHIFT));
      }

      static SIMD_2x64 BOTAN_SIMD_2X64_FN alignr8(const SIMD_2x64& a, const SIMD_2x64& b) {
         return SIMD_2x64(_mm_alignr_epi8(a.m_simd, b.m_simd, 8));
      }

      // Argon2 specific operation
      static void twist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         SIMD_2x64 T0, T1;

         T0 = SIMD_2x64::alignr8(B1, B0);
         T1 = SIMD_2x64::alignr8(B0, B1);
         B0 = T0;
         B1 = T1;

         T0 = C0;
         C0 = C1;
         C1 = T0;

         T0 = SIMD_2x64::alignr8(D0, D1);
         T1 = SIMD_2x64::alignr8(D1, D0);
         D0 = T0;
         D1 = T1;
      }

      // Argon2 specific operation
      static void untwist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         SIMD_2x64 T0, T1;

         T0 = SIMD_2x64::alignr8(B0, B1);
         T1 = SIMD_2x64::alignr8(B1, B0);
         B0 = T0;
         B1 = T1;

         T0 = C0;
         C0 = C1;
         C1 = T0;

         T0 = SIMD_2x64::alignr8(D1, D0);
         T1 = SIMD_2x64::alignr8(D0, D1);
         D0 = T0;
         D1 = T1;
      }

      // Argon2 specific operation
      static SIMD_2x64 mul2_32(SIMD_2x64 x, SIMD_2x64 y) {
         const __m128i m = _mm_mul_epu32(x.m_simd, y.m_simd);
         return SIMD_2x64(_mm_add_epi64(m, m));
      }

      explicit SIMD_2x64(__m128i x) : m_simd(x) {}

   private:
      __m128i m_simd;
};

}  // namespace Botan

#endif
