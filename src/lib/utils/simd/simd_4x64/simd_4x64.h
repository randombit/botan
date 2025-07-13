/*
* (C) 2022,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_4X64_H_
#define BOTAN_SIMD_4X64_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/target_info.h>

#if defined(BOTAN_TARGET_CPU_SUPPORTS_AVX2)
   #include <immintrin.h>
#endif

namespace Botan {

// NOLINTBEGIN(portability-simd-intrinsics)

class SIMD_4x64 final {
   public:
      SIMD_4x64& operator=(const SIMD_4x64& other) = default;
      SIMD_4x64(const SIMD_4x64& other) = default;

      SIMD_4x64& operator=(SIMD_4x64&& other) = default;
      SIMD_4x64(SIMD_4x64&& other) = default;

      ~SIMD_4x64() = default;

      // zero initialized
      BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64() : m_simd(_mm256_setzero_si256()) {}

      // Load two halves at different addresses
      static BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 load_le2(const void* inl, const void* inh) {
         return SIMD_4x64(
            _mm256_loadu2_m128i(reinterpret_cast<const __m128i*>(inl), reinterpret_cast<const __m128i*>(inh)));
      }

      static BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 load_be2(const void* inl, const void* inh) {
         return SIMD_4x64::load_le2(inl, inh).bswap();
      }

      static BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 load_le(const void* in) {
         return SIMD_4x64(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(in)));
      }

      static BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 load_be(const void* in) { return SIMD_4x64::load_le(in).bswap(); }

      SIMD_4x64 BOTAN_FN_ISA_SIMD_4X64 bswap() const {
         const auto idx = _mm256_set_epi8(
            8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);

         return SIMD_4x64(_mm256_shuffle_epi8(m_simd, idx));
      }

      void store_le(uint64_t out[4]) const { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      BOTAN_FN_ISA_SIMD_4X64 void store_le(uint8_t out[]) const {
         _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), m_simd);
      }

      BOTAN_FN_ISA_SIMD_4X64 void store_le2(void* outh, void* outl) {
         _mm256_storeu2_m128i(reinterpret_cast<__m128i*>(outh), reinterpret_cast<__m128i*>(outl), m_simd);
      }

      SIMD_4x64 operator+(const SIMD_4x64& other) const {
         SIMD_4x64 retval(*this);
         retval += other;
         return retval;
      }

      SIMD_4x64 operator^(const SIMD_4x64& other) const {
         SIMD_4x64 retval(*this);
         retval ^= other;
         return retval;
      }

      BOTAN_FN_ISA_SIMD_4X64 void operator+=(const SIMD_4x64& other) {
         m_simd = _mm256_add_epi64(m_simd, other.m_simd);
      }

      BOTAN_FN_ISA_SIMD_4X64 void operator^=(const SIMD_4x64& other) {
         m_simd = _mm256_xor_si256(m_simd, other.m_simd);
      }

      template <size_t ROT>
      BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
#if defined(__AVX512VL__)
         return SIMD_4x64(_mm256_ror_epi64(m_simd, ROT));
#else
         if constexpr(ROT == 8) {
            auto shuf_rot_8 =
               _mm256_set_epi64x(0x080f0e0d0c0b0a09, 0x0007060504030201, 0x080f0e0d0c0b0a09, 0x0007060504030201);

            return SIMD_4x64(_mm256_shuffle_epi8(m_simd, shuf_rot_8));
         } else if constexpr(ROT == 16) {
            auto shuf_rot_16 =
               _mm256_set_epi64x(0x09080f0e0d0c0b0a, 0x0100070605040302, 0x09080f0e0d0c0b0a, 0x0100070605040302);

            return SIMD_4x64(_mm256_shuffle_epi8(m_simd, shuf_rot_16));
         } else if constexpr(ROT == 24) {
            auto shuf_rot_24 =
               _mm256_set_epi64x(0x0a09080f0e0d0c0b, 0x0201000706050403, 0x0a09080f0e0d0c0b, 0x0201000706050403);

            return SIMD_4x64(_mm256_shuffle_epi8(m_simd, shuf_rot_24));
         } else if constexpr(ROT == 32) {
            auto shuf_rot_32 =
               _mm256_set_epi64x(0x0b0a09080f0e0d0c, 0x0302010007060504, 0x0b0a09080f0e0d0c, 0x0302010007060504);

            return SIMD_4x64(_mm256_shuffle_epi8(m_simd, shuf_rot_32));
         } else {
            return SIMD_4x64(_mm256_or_si256(_mm256_srli_epi64(m_simd, static_cast<int>(ROT)),
                                             _mm256_slli_epi64(m_simd, static_cast<int>(64 - ROT))));
         }
#endif
      }

      template <size_t ROT>
      SIMD_4x64 rotl() const {
         return this->rotr<64 - ROT>();
      }

      template <int SHIFT>
      SIMD_4x64 BOTAN_FN_ISA_SIMD_4X64 shr() const noexcept {
         return SIMD_4x64(_mm256_srli_epi64(m_simd, SHIFT));
      }

      static SIMD_4x64 BOTAN_FN_ISA_SIMD_4X64 alignr8(const SIMD_4x64& a, const SIMD_4x64& b) {
         return SIMD_4x64(_mm256_alignr_epi8(a.m_simd, b.m_simd, 8));
      }

      // Argon2 specific operation
      static BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 mul2_32(SIMD_4x64 x, SIMD_4x64 y) {
         const __m256i m = _mm256_mul_epu32(x.m_simd, y.m_simd);
         return SIMD_4x64(_mm256_add_epi64(m, m));
      }

      template <uint8_t CTRL>
      static BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64 permute_4x64(SIMD_4x64 x) {
         return SIMD_4x64(_mm256_permute4x64_epi64(x.m_simd, CTRL));
      }

      // Argon2 specific
      static void twist(SIMD_4x64& B, SIMD_4x64& C, SIMD_4x64& D) {
         B = SIMD_4x64::permute_4x64<0b00'11'10'01>(B);
         C = SIMD_4x64::permute_4x64<0b01'00'11'10>(C);
         D = SIMD_4x64::permute_4x64<0b10'01'00'11>(D);
      }

      // Argon2 specific
      static void untwist(SIMD_4x64& B, SIMD_4x64& C, SIMD_4x64& D) {
         B = SIMD_4x64::permute_4x64<0b10'01'00'11>(B);
         C = SIMD_4x64::permute_4x64<0b01'00'11'10>(C);
         D = SIMD_4x64::permute_4x64<0b00'11'10'01>(D);
      }

      explicit BOTAN_FN_ISA_SIMD_4X64 SIMD_4x64(__m256i x) : m_simd(x) {}

   private:
      __m256i m_simd;
};

// NOLINTEND(portability-simd-intrinsics)

}  // namespace Botan

#endif
