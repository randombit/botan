/*
* (C) 2022,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_8X64_H_
#define BOTAN_SIMD_8X64_H_

#include <botan/types.h>
#include <botan/internal/isa_extn.h>
#include <immintrin.h>

namespace Botan {

// NOLINTBEGIN(portability-simd-intrinsics)

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

      BOTAN_FN_ISA_AVX512
      static SIMD_8x64 broadcast_2x64(const uint64_t* in) {
         return SIMD_8x64(_mm512_broadcast_i64x2(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in))));
      }

      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 load_be(const void* in) { return SIMD_8x64::load_le(in).bswap(); }

      /**
      * Load in big endian order from ptrs[i] + Stride * n + offset,
      * gathering lane i's n'th block out of a set of per lane buffers
      */
      template <size_t Stride>
      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64
      load_be(const uint8_t* const* ptrs, size_t i, size_t n, size_t offset = 0) {
         return load_be(ptrs[i] + Stride * n + offset);
      }

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

      BOTAN_FN_ISA_SIMD_8X64 void store_be(uint8_t out[]) const { bswap().store_le(out); }

      BOTAN_FN_ISA_SIMD_8X64 void store_le4(void* out0, void* out1, void* out2, void* out3) {
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out0), _mm512_extracti32x4_epi32(m_simd, 3));
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out1), _mm512_extracti32x4_epi32(m_simd, 2));
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out2), _mm512_extracti32x4_epi32(m_simd, 1));
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out3), _mm512_extracti32x4_epi32(m_simd, 0));
      }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 operator+(const SIMD_8x64& other) const {
         SIMD_8x64 retval(*this);
         retval += other;
         return retval;
      }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 operator^(const SIMD_8x64& other) const {
         SIMD_8x64 retval(*this);
         retval ^= other;
         return retval;
      }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 operator&(const SIMD_8x64& other) const {
         SIMD_8x64 retval(*this);
         retval &= other;
         return retval;
      }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 operator|(const SIMD_8x64& other) const {
         SIMD_8x64 retval(*this);
         retval |= other;
         return retval;
      }

      BOTAN_FN_ISA_SIMD_8X64 void operator+=(const SIMD_8x64& other) {
         m_simd = _mm512_add_epi64(m_simd, other.m_simd);
      }

      BOTAN_FN_ISA_SIMD_8X64 void operator^=(const SIMD_8x64& other) {
         m_simd = _mm512_xor_si512(m_simd, other.m_simd);
      }

      BOTAN_FN_ISA_SIMD_8X64 void operator&=(const SIMD_8x64& other) {
         m_simd = _mm512_and_si512(m_simd, other.m_simd);
      }

      BOTAN_FN_ISA_SIMD_8X64 void operator|=(const SIMD_8x64& other) { m_simd = _mm512_or_si512(m_simd, other.m_simd); }

      // (~reg) & other
      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 andc(const SIMD_8x64& other) const {
         return SIMD_8x64(_mm512_andnot_si512(m_simd, other.m_simd));
      }

      /**
      * The Keccak chi operation, x ^ (~y & z)
      */
      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 chi(const SIMD_8x64& x, const SIMD_8x64& y, const SIMD_8x64& z) {
         constexpr uint8_t xor_not_and = 0b11010010;
         return SIMD_8x64(_mm512_ternarylogic_epi64(x.m_simd, y.m_simd, z.m_simd, xor_not_and));
      }

      template <size_t ROT>
      BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
         return SIMD_8x64(_mm512_ror_epi64(m_simd, ROT));
      }

      template <size_t ROT>
      BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 rotl() const {
         return this->rotr<64 - ROT>();
      }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 sigma0() const {
         const SIMD_8x64 r1 = this->rotr<28>();
         const SIMD_8x64 r2 = this->rotr<34>();
         const SIMD_8x64 r3 = this->rotr<39>();
         return r1 ^ r2 ^ r3;
      }

      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 sigma1() const {
         const SIMD_8x64 r1 = this->rotr<14>();
         const SIMD_8x64 r2 = this->rotr<18>();
         const SIMD_8x64 r3 = this->rotr<41>();
         return r1 ^ r2 ^ r3;
      }

      BOTAN_FN_ISA_SIMD_8X64
      static SIMD_8x64 choose(const SIMD_8x64& mask, const SIMD_8x64& a, const SIMD_8x64& b) {
         return SIMD_8x64(_mm512_ternarylogic_epi64(mask.raw(), a.raw(), b.raw(), 0xca));
      }

      BOTAN_FN_ISA_SIMD_8X64
      static SIMD_8x64 majority(const SIMD_8x64& x, const SIMD_8x64& y, const SIMD_8x64& z) {
         return SIMD_8x64(_mm512_ternarylogic_epi64(x.raw(), y.raw(), z.raw(), 0xe8));
      }

      BOTAN_FN_ISA_SIMD_8X64
      static void transpose(SIMD_8x64& B0,
                            SIMD_8x64& B1,
                            SIMD_8x64& B2,
                            SIMD_8x64& B3,
                            SIMD_8x64& B4,
                            SIMD_8x64& B5,
                            SIMD_8x64& B6,
                            SIMD_8x64& B7) {
         const auto t0 = _mm512_unpacklo_epi64(B0.m_simd, B1.m_simd);
         const auto t1 = _mm512_unpackhi_epi64(B0.m_simd, B1.m_simd);
         const auto t2 = _mm512_unpacklo_epi64(B2.m_simd, B3.m_simd);
         const auto t3 = _mm512_unpackhi_epi64(B2.m_simd, B3.m_simd);
         const auto t4 = _mm512_unpacklo_epi64(B4.m_simd, B5.m_simd);
         const auto t5 = _mm512_unpackhi_epi64(B4.m_simd, B5.m_simd);
         const auto t6 = _mm512_unpacklo_epi64(B6.m_simd, B7.m_simd);
         const auto t7 = _mm512_unpackhi_epi64(B6.m_simd, B7.m_simd);

         const auto s0 = _mm512_shuffle_i64x2(t0, t2, 0x88);
         const auto s1 = _mm512_shuffle_i64x2(t1, t3, 0x88);
         const auto s2 = _mm512_shuffle_i64x2(t0, t2, 0xdd);
         const auto s3 = _mm512_shuffle_i64x2(t1, t3, 0xdd);
         const auto s4 = _mm512_shuffle_i64x2(t4, t6, 0x88);
         const auto s5 = _mm512_shuffle_i64x2(t5, t7, 0x88);
         const auto s6 = _mm512_shuffle_i64x2(t4, t6, 0xdd);
         const auto s7 = _mm512_shuffle_i64x2(t5, t7, 0xdd);

         B0.m_simd = _mm512_shuffle_i64x2(s0, s4, 0x88);
         B1.m_simd = _mm512_shuffle_i64x2(s1, s5, 0x88);
         B2.m_simd = _mm512_shuffle_i64x2(s2, s6, 0x88);
         B3.m_simd = _mm512_shuffle_i64x2(s3, s7, 0x88);
         B4.m_simd = _mm512_shuffle_i64x2(s0, s4, 0xdd);
         B5.m_simd = _mm512_shuffle_i64x2(s1, s5, 0xdd);
         B6.m_simd = _mm512_shuffle_i64x2(s2, s6, 0xdd);
         B7.m_simd = _mm512_shuffle_i64x2(s3, s7, 0xdd);
      }

      template <int SHIFT>
      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 shr() const noexcept {
         return SIMD_8x64(_mm512_srli_epi64(m_simd, SHIFT));
      }

      template <int SHIFT>
      SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 shl() const noexcept {
         return SIMD_8x64(_mm512_slli_epi64(m_simd, SHIFT));
      }

      static SIMD_8x64 BOTAN_FN_ISA_SIMD_8X64 alignr8(const SIMD_8x64& a, const SIMD_8x64& b) {
         return SIMD_8x64(_mm512_alignr_epi8(a.m_simd, b.m_simd, 8));
      }

      BOTAN_FN_ISA_SIMD_8X64
      static SIMD_8x64 splat(uint64_t v) { return SIMD_8x64(_mm512_set1_epi64(v)); }

      // Argon2 specific operation
      static BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64 mul2_32(SIMD_8x64 x, SIMD_8x64 y) {
         const __m512i m = _mm512_mul_epu32(x.m_simd, y.m_simd);
         return SIMD_8x64(_mm512_add_epi64(m, m));
      }

      // Argon2 specific - twist/untwist permutes within two independent 4-lane groups
      static void BOTAN_FN_ISA_SIMD_8X64 twist(SIMD_8x64& B, SIMD_8x64& C, SIMD_8x64& D) {
         const auto b_perm = _mm512_set_epi64(4, 7, 6, 5, 0, 3, 2, 1);
         const auto c_perm = _mm512_set_epi64(5, 4, 7, 6, 1, 0, 3, 2);
         const auto d_perm = _mm512_set_epi64(6, 5, 4, 7, 2, 1, 0, 3);
         B = SIMD_8x64(_mm512_permutexvar_epi64(b_perm, B.m_simd));
         C = SIMD_8x64(_mm512_permutexvar_epi64(c_perm, C.m_simd));
         D = SIMD_8x64(_mm512_permutexvar_epi64(d_perm, D.m_simd));
      }

      static void BOTAN_FN_ISA_SIMD_8X64 untwist(SIMD_8x64& B, SIMD_8x64& C, SIMD_8x64& D) {
         const auto b_perm = _mm512_set_epi64(6, 5, 4, 7, 2, 1, 0, 3);
         const auto c_perm = _mm512_set_epi64(5, 4, 7, 6, 1, 0, 3, 2);
         const auto d_perm = _mm512_set_epi64(4, 7, 6, 5, 0, 3, 2, 1);
         B = SIMD_8x64(_mm512_permutexvar_epi64(b_perm, B.m_simd));
         C = SIMD_8x64(_mm512_permutexvar_epi64(c_perm, C.m_simd));
         D = SIMD_8x64(_mm512_permutexvar_epi64(d_perm, D.m_simd));
      }

      __m512i BOTAN_FN_ISA_SIMD_8X64 raw() const noexcept { return m_simd; }

      explicit BOTAN_FN_ISA_SIMD_8X64 SIMD_8x64(__m512i x) : m_simd(x) {}

   private:
      __m512i m_simd;
};

// NOLINTEND(portability-simd-intrinsics)

}  // namespace Botan

#endif
