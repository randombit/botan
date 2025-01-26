/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_AVX2_H_
#define BOTAN_SIMD_AVX2_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <immintrin.h>

namespace Botan {

#define BOTAN_AVX2_FN BOTAN_FUNC_ISA("avx2")

class SIMD_8x32 final {
   public:
      SIMD_8x32& operator=(const SIMD_8x32& other) = default;
      SIMD_8x32(const SIMD_8x32& other) = default;

      SIMD_8x32& operator=(SIMD_8x32&& other) = default;
      SIMD_8x32(SIMD_8x32&& other) = default;

      ~SIMD_8x32() = default;

      BOTAN_AVX2_FN
      BOTAN_FORCE_INLINE SIMD_8x32() noexcept { m_avx2 = _mm256_setzero_si256(); }

      BOTAN_AVX2_FN
      explicit SIMD_8x32(const uint32_t B[8]) noexcept {
         m_avx2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(B));
      }

      BOTAN_AVX2_FN
      explicit SIMD_8x32(uint32_t B0,
                         uint32_t B1,
                         uint32_t B2,
                         uint32_t B3,
                         uint32_t B4,
                         uint32_t B5,
                         uint32_t B6,
                         uint32_t B7) noexcept {
         m_avx2 = _mm256_set_epi32(B7, B6, B5, B4, B3, B2, B1, B0);
      }

      BOTAN_AVX2_FN
      static SIMD_8x32 splat(uint32_t B) noexcept { return SIMD_8x32(_mm256_set1_epi32(B)); }

      BOTAN_AVX2_FN
      static SIMD_8x32 load_le(const uint8_t* in) noexcept {
         return SIMD_8x32(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(in)));
      }

      BOTAN_AVX2_FN
      static SIMD_8x32 load_le128(const uint8_t* in) noexcept {
         return SIMD_8x32(_mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in))));
      }

      BOTAN_AVX2_FN
      static SIMD_8x32 load_le128(const uint32_t* in) noexcept {
         return SIMD_8x32(_mm256_broadcastsi128_si256(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in))));
      }

      BOTAN_AVX2_FN
      static SIMD_8x32 load_be(const uint8_t* in) noexcept { return load_le(in).bswap(); }

      BOTAN_AVX2_FN
      void store_le(uint8_t out[]) const noexcept { _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), m_avx2); }

      BOTAN_AVX2_FN
      void store_le128(uint8_t out[]) const noexcept {
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm256_extracti128_si256(raw(), 0));
      }

      BOTAN_AVX2_FN
      void store_be(uint8_t out[]) const noexcept { bswap().store_le(out); }

      template <size_t ROT>
      BOTAN_AVX2_FN SIMD_8x32 rotl() const noexcept
         requires(ROT > 0 && ROT < 32)
      {
#if defined(__AVX512VL__)
         return SIMD_8x32(_mm256_rol_epi32(m_avx2, ROT));
#else
         if constexpr(ROT == 8) {
            const __m256i shuf_rotl_8 =
               _mm256_set_epi64x(0x0e0d0c0f'0a09080b, 0x06050407'02010003, 0x0e0d0c0f'0a09080b, 0x06050407'02010003);

            return SIMD_8x32(_mm256_shuffle_epi8(m_avx2, shuf_rotl_8));
         } else if constexpr(ROT == 16) {
            const __m256i shuf_rotl_16 =
               _mm256_set_epi64x(0x0d0c0f0e'09080b0a, 0x05040706'01000302, 0x0d0c0f0e'09080b0a, 0x05040706'01000302);

            return SIMD_8x32(_mm256_shuffle_epi8(m_avx2, shuf_rotl_16));
         } else if constexpr(ROT == 24) {
            const __m256i shuf_rotl_24 =
               _mm256_set_epi64x(0x0c0f0e0d'080b0a09, 0x04070605'00030201, 0x0c0f0e0d'080b0a09, 0x04070605'00030201);

            return SIMD_8x32(_mm256_shuffle_epi8(m_avx2, shuf_rotl_24));
         } else {
            return SIMD_8x32(_mm256_or_si256(_mm256_slli_epi32(m_avx2, static_cast<int>(ROT)),
                                             _mm256_srli_epi32(m_avx2, static_cast<int>(32 - ROT))));
         }
#endif
      }

      template <size_t ROT>
      BOTAN_AVX2_FN SIMD_8x32 rotr() const noexcept {
         return this->rotl<32 - ROT>();
      }

      SIMD_8x32 BOTAN_AVX2_FN sigma0() const noexcept {
         const SIMD_8x32 rot1 = this->rotr<2>();
         const SIMD_8x32 rot2 = this->rotr<13>();
         const SIMD_8x32 rot3 = this->rotr<22>();
         return rot1 ^ rot2 ^ rot3;
      }

      SIMD_8x32 BOTAN_AVX2_FN sigma1() const noexcept {
         const SIMD_8x32 rot1 = this->rotr<6>();
         const SIMD_8x32 rot2 = this->rotr<11>();
         const SIMD_8x32 rot3 = this->rotr<25>();
         return rot1 ^ rot2 ^ rot3;
      }

      BOTAN_AVX2_FN
      SIMD_8x32 operator+(const SIMD_8x32& other) const noexcept {
         SIMD_8x32 retval(*this);
         retval += other;
         return retval;
      }

      BOTAN_AVX2_FN
      SIMD_8x32 operator-(const SIMD_8x32& other) const noexcept {
         SIMD_8x32 retval(*this);
         retval -= other;
         return retval;
      }

      BOTAN_AVX2_FN
      SIMD_8x32 operator^(const SIMD_8x32& other) const noexcept {
         SIMD_8x32 retval(*this);
         retval ^= other;
         return retval;
      }

      BOTAN_AVX2_FN
      SIMD_8x32 operator|(const SIMD_8x32& other) const noexcept {
         SIMD_8x32 retval(*this);
         retval |= other;
         return retval;
      }

      BOTAN_AVX2_FN
      SIMD_8x32 operator&(const SIMD_8x32& other) const noexcept {
         SIMD_8x32 retval(*this);
         retval &= other;
         return retval;
      }

      BOTAN_AVX2_FN
      void operator+=(const SIMD_8x32& other) { m_avx2 = _mm256_add_epi32(m_avx2, other.m_avx2); }

      BOTAN_AVX2_FN
      void operator-=(const SIMD_8x32& other) { m_avx2 = _mm256_sub_epi32(m_avx2, other.m_avx2); }

      BOTAN_AVX2_FN
      void operator^=(const SIMD_8x32& other) { m_avx2 = _mm256_xor_si256(m_avx2, other.m_avx2); }

      BOTAN_AVX2_FN
      void operator^=(uint32_t other) { *this ^= SIMD_8x32::splat(other); }

      BOTAN_AVX2_FN
      void operator|=(const SIMD_8x32& other) { m_avx2 = _mm256_or_si256(m_avx2, other.m_avx2); }

      BOTAN_AVX2_FN
      void operator&=(const SIMD_8x32& other) { m_avx2 = _mm256_and_si256(m_avx2, other.m_avx2); }

      template <int SHIFT>
      BOTAN_AVX2_FN SIMD_8x32 shl() const noexcept {
         return SIMD_8x32(_mm256_slli_epi32(m_avx2, SHIFT));
      }

      template <int SHIFT>
      BOTAN_AVX2_FN SIMD_8x32 shr() const noexcept {
         return SIMD_8x32(_mm256_srli_epi32(m_avx2, SHIFT));
      }

      BOTAN_AVX2_FN
      SIMD_8x32 operator~() const noexcept {
         return SIMD_8x32(_mm256_xor_si256(m_avx2, _mm256_set1_epi32(0xFFFFFFFF)));
      }

      // (~reg) & other
      BOTAN_AVX2_FN
      SIMD_8x32 andc(const SIMD_8x32& other) const noexcept {
         return SIMD_8x32(_mm256_andnot_si256(m_avx2, other.m_avx2));
      }

      BOTAN_AVX2_FN
      SIMD_8x32 bswap() const noexcept {
         const uint8_t BSWAP_MASK[32] = {3,  2,  1,  0,  7,  6,  5,  4,  11, 10, 9,  8,  15, 14, 13, 12,
                                         19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28};

         const __m256i bswap = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(BSWAP_MASK));

         const __m256i output = _mm256_shuffle_epi8(m_avx2, bswap);

         return SIMD_8x32(output);
      }

      BOTAN_AVX2_FN
      SIMD_8x32 rev_words() const noexcept { return SIMD_8x32(_mm256_shuffle_epi32(raw(), 0b00011011)); }

      BOTAN_AVX2_FN
      static void transpose(SIMD_8x32& B0, SIMD_8x32& B1, SIMD_8x32& B2, SIMD_8x32& B3) noexcept {
         const __m256i T0 = _mm256_unpacklo_epi32(B0.m_avx2, B1.m_avx2);
         const __m256i T1 = _mm256_unpacklo_epi32(B2.m_avx2, B3.m_avx2);
         const __m256i T2 = _mm256_unpackhi_epi32(B0.m_avx2, B1.m_avx2);
         const __m256i T3 = _mm256_unpackhi_epi32(B2.m_avx2, B3.m_avx2);

         B0.m_avx2 = _mm256_unpacklo_epi64(T0, T1);
         B1.m_avx2 = _mm256_unpackhi_epi64(T0, T1);
         B2.m_avx2 = _mm256_unpacklo_epi64(T2, T3);
         B3.m_avx2 = _mm256_unpackhi_epi64(T2, T3);
      }

      BOTAN_AVX2_FN
      static void transpose(SIMD_8x32& B0,
                            SIMD_8x32& B1,
                            SIMD_8x32& B2,
                            SIMD_8x32& B3,
                            SIMD_8x32& B4,
                            SIMD_8x32& B5,
                            SIMD_8x32& B6,
                            SIMD_8x32& B7) noexcept {
         transpose(B0, B1, B2, B3);
         transpose(B4, B5, B6, B7);

         swap_tops(B0, B4);
         swap_tops(B1, B5);
         swap_tops(B2, B6);
         swap_tops(B3, B7);
      }

      BOTAN_AVX2_FN
      static SIMD_8x32 choose(const SIMD_8x32& mask, const SIMD_8x32& a, const SIMD_8x32& b) noexcept {
#if defined(__AVX512VL__)
         return _mm256_ternarylogic_epi32(mask.raw(), a.raw(), b.raw(), 0xca);
#else
         return (mask & a) ^ mask.andc(b);
#endif
      }

      BOTAN_AVX2_FN
      static SIMD_8x32 majority(const SIMD_8x32& x, const SIMD_8x32& y, const SIMD_8x32& z) noexcept {
#if defined(__AVX512VL__)
         return _mm256_ternarylogic_epi32(x.raw(), y.raw(), z.raw(), 0xe8);
#else
         return SIMD_8x32::choose(x ^ y, z, y);
#endif
      }

      BOTAN_AVX2_FN
      static void reset_registers() noexcept { _mm256_zeroupper(); }

      BOTAN_AVX2_FN
      static void zero_registers() noexcept { _mm256_zeroall(); }

      __m256i BOTAN_AVX2_FN raw() const noexcept { return m_avx2; }

      BOTAN_AVX2_FN
      SIMD_8x32(__m256i x) noexcept : m_avx2(x) {}

   private:
      BOTAN_AVX2_FN
      static void swap_tops(SIMD_8x32& A, SIMD_8x32& B) {
         SIMD_8x32 T0 = _mm256_permute2x128_si256(A.raw(), B.raw(), 0 + (2 << 4));
         SIMD_8x32 T1 = _mm256_permute2x128_si256(A.raw(), B.raw(), 1 + (3 << 4));
         A = T0;
         B = T1;
      }

      __m256i m_avx2;
};

template <size_t R>
inline SIMD_8x32 rotl(SIMD_8x32 input) {
   return input.rotl<R>();
}

template <size_t R>
inline SIMD_8x32 rotr(SIMD_8x32 input) {
   return input.rotr<R>();
}

// For Serpent:
template <size_t S>
inline SIMD_8x32 shl(SIMD_8x32 input) {
   return input.shl<S>();
}

}  // namespace Botan

#endif
