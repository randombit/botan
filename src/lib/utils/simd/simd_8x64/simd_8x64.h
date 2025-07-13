/*
* (C) 2022,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_8X64_H_
#define BOTAN_SIMD_8X64_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/target_info.h>
#include <immintrin.h>

namespace Botan {

class SIMD_8x64 final {
   public:
      SIMD_8x64& operator=(const SIMD_8x64& other) = default;
      SIMD_8x64(const SIMD_8x64& other) = default;

      SIMD_8x64& operator=(SIMD_8x64&& other) = default;
      SIMD_8x64(SIMD_8x64&& other) = default;

      ~SIMD_8x64() = default;

      // zero initialized
      BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64() : m_simd(_mm512_setzero_si512()) {}

      // Load two halves at different addresses
      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 load_le4(const void* in0,
                                                       const void* in1,
                                                       const void* in2,
                                                       const void* in3) {
         auto r = _mm512_setzero_si512();
         r = _mm512_inserti32x4(r, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in0)), 3);
         r = _mm512_inserti32x4(r, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in1)), 2);
         r = _mm512_inserti32x4(r, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in2)), 1);
         r = _mm512_inserti32x4(r, _mm_loadu_si128(reinterpret_cast<const __m128i*>(in3)), 0);
         return SIMD_8x64(r);
      }

      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 load_be4(const void* in0,
                                                       const void* in1,
                                                       const void* in2,
                                                       const void* in3) {
         return SIMD_8x64::load_le4(in0, in1, in2, in3).bswap();
      }

      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 load_le(const void* in) {
         return SIMD_8x64(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(in)));
      }

      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 load_be(const void* in) { return SIMD_8x64::load_le(in).bswap(); }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 bswap() const {
         // clang-format off
         const auto idx = _mm512_set_epi8(
            8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
         // clang-format on

         return SIMD_8x64(_mm512_shuffle_epi8(m_simd, idx));
      }

      void store_le(uint64_t out[8]) const { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      BOTAN_FN_ISA_SIMD_8X64 void store_le(uint8_t out[]) const {
         _mm512_storeu_si512(reinterpret_cast<__m512i*>(out), m_simd);
      }

      BOTAN_FN_ISA_SIMD_8X64 void store_le4(void* out0, void* out1, void* out2, void* out3) {
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out0), _mm512_extracti32x4_epi32(m_simd, 3));
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out1), _mm512_extracti32x4_epi32(m_simd, 2));
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out2), _mm512_extracti32x4_epi32(m_simd, 1));
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out3), _mm512_extracti32x4_epi32(m_simd, 0));
      }

      SIMD_8x64 operator+(const SIMD_8x64& other) const {
         SIMD_8x64 retval(*this);
         retval += other;
         return retval;
      }

      SIMD_8x64 operator^(const SIMD_8x64& other) const {
         SIMD_8x64 retval(*this);
         retval ^= other;
         return retval;
      }

      BOTAN_FN_ISA_SIMD_8X64 void operator+=(const SIMD_8x64& other) {
         m_simd = _mm512_add_epi64(m_simd, other.m_simd);
      }

      BOTAN_FN_ISA_SIMD_8X64 void operator^=(const SIMD_8x64& other) {
         m_simd = _mm512_xor_si512(m_simd, other.m_simd);
      }

      template <size_t ROT>
      BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
         return SIMD_8x64(_mm512_ror_epi64(m_simd, ROT));
      }

      template <size_t ROT>
      SIMD_8x64 rotl() const {
         return this->rotr<64 - ROT>();
      }

      template <int SHIFT>
      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 shr() const noexcept {
         return SIMD_8x64(_mm512_srli_epi64(m_simd, SHIFT));
      }

      static SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 alignr8(const SIMD_8x64& a, const SIMD_8x64& b) {
         return SIMD_8x64(_mm512_alignr_epi8(a.m_simd, b.m_simd, 8));
      }

      explicit BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64(__m512i x) : m_simd(x) {}

   private:
      __m512i m_simd;
};

}  // namespace Botan

#endif
