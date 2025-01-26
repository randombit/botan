/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_AVX512_H_
#define BOTAN_SIMD_AVX512_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <immintrin.h>

namespace Botan {

#define BOTAN_AVX512_FN BOTAN_FUNC_ISA("avx512f,avx512dq,avx512bw")

class SIMD_16x32 final {
   public:
      SIMD_16x32& operator=(const SIMD_16x32& other) = default;
      SIMD_16x32(const SIMD_16x32& other) = default;

      SIMD_16x32& operator=(SIMD_16x32&& other) = default;
      SIMD_16x32(SIMD_16x32&& other) = default;

      BOTAN_AVX512_FN
      BOTAN_FORCE_INLINE SIMD_16x32() { m_avx512 = _mm512_setzero_si512(); }

      BOTAN_AVX512_FN
      explicit SIMD_16x32(const uint32_t B[16]) { m_avx512 = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(B)); }

      BOTAN_AVX512_FN
      explicit SIMD_16x32(uint32_t B0,
                          uint32_t B1,
                          uint32_t B2,
                          uint32_t B3,
                          uint32_t B4,
                          uint32_t B5,
                          uint32_t B6,
                          uint32_t B7,
                          uint32_t B8,
                          uint32_t B9,
                          uint32_t BA,
                          uint32_t BB,
                          uint32_t BC,
                          uint32_t BD,
                          uint32_t BE,
                          uint32_t BF) {
         m_avx512 = _mm512_set_epi32(BF, BE, BD, BC, BB, BA, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0);
      }

      BOTAN_AVX512_FN
      static SIMD_16x32 splat(uint32_t B) { return SIMD_16x32(_mm512_set1_epi32(B)); }

      BOTAN_AVX512_FN
      static SIMD_16x32 load_le(const uint8_t* in) {
         return SIMD_16x32(_mm512_loadu_si512(reinterpret_cast<const __m512i*>(in)));
      }

      BOTAN_AVX512_FN
      static SIMD_16x32 load_be(const uint8_t* in) { return load_le(in).bswap(); }

      BOTAN_AVX512_FN
      void store_le(uint8_t out[]) const { _mm512_storeu_si512(reinterpret_cast<__m512i*>(out), m_avx512); }

      BOTAN_AVX512_FN
      void store_be(uint8_t out[]) const { bswap().store_le(out); }

      template <size_t ROT>
      BOTAN_AVX512_FN SIMD_16x32 rotl() const
         requires(ROT > 0 && ROT < 32)
      {
         return SIMD_16x32(_mm512_rol_epi32(m_avx512, ROT));
      }

      template <size_t ROT>
      BOTAN_AVX512_FN SIMD_16x32 rotr() const {
         return this->rotl<32 - ROT>();
      }

      SIMD_16x32 BOTAN_AVX512_FN sigma0() const {
         const SIMD_16x32 rot1 = this->rotr<2>();
         const SIMD_16x32 rot2 = this->rotr<13>();
         const SIMD_16x32 rot3 = this->rotr<22>();
         return rot1 ^ rot2 ^ rot3;
      }

      SIMD_16x32 BOTAN_AVX512_FN sigma1() const {
         const SIMD_16x32 rot1 = this->rotr<6>();
         const SIMD_16x32 rot2 = this->rotr<11>();
         const SIMD_16x32 rot3 = this->rotr<25>();
         return rot1 ^ rot2 ^ rot3;
      }

      BOTAN_AVX512_FN
      SIMD_16x32 operator+(const SIMD_16x32& other) const {
         SIMD_16x32 retval(*this);
         retval += other;
         return retval;
      }

      BOTAN_AVX512_FN
      SIMD_16x32 operator-(const SIMD_16x32& other) const {
         SIMD_16x32 retval(*this);
         retval -= other;
         return retval;
      }

      BOTAN_AVX512_FN
      SIMD_16x32 operator^(const SIMD_16x32& other) const {
         SIMD_16x32 retval(*this);
         retval ^= other;
         return retval;
      }

      BOTAN_AVX512_FN
      SIMD_16x32 operator|(const SIMD_16x32& other) const {
         SIMD_16x32 retval(*this);
         retval |= other;
         return retval;
      }

      BOTAN_AVX512_FN
      SIMD_16x32 operator&(const SIMD_16x32& other) const {
         SIMD_16x32 retval(*this);
         retval &= other;
         return retval;
      }

      BOTAN_AVX512_FN
      void operator+=(const SIMD_16x32& other) { m_avx512 = _mm512_add_epi32(m_avx512, other.m_avx512); }

      BOTAN_AVX512_FN
      void operator-=(const SIMD_16x32& other) { m_avx512 = _mm512_sub_epi32(m_avx512, other.m_avx512); }

      BOTAN_AVX512_FN
      void operator^=(const SIMD_16x32& other) { m_avx512 = _mm512_xor_si512(m_avx512, other.m_avx512); }

      BOTAN_AVX512_FN
      void operator^=(uint32_t other) { *this ^= SIMD_16x32::splat(other); }

      BOTAN_AVX512_FN
      void operator|=(const SIMD_16x32& other) { m_avx512 = _mm512_or_si512(m_avx512, other.m_avx512); }

      BOTAN_AVX512_FN
      void operator&=(const SIMD_16x32& other) { m_avx512 = _mm512_and_si512(m_avx512, other.m_avx512); }

      template <int SHIFT>
      BOTAN_AVX512_FN SIMD_16x32 shl() const {
         return SIMD_16x32(_mm512_slli_epi32(m_avx512, SHIFT));
      }

      template <int SHIFT>
      BOTAN_AVX512_FN SIMD_16x32 shr() const {
         return SIMD_16x32(_mm512_srli_epi32(m_avx512, SHIFT));
      }

      BOTAN_AVX512_FN
      SIMD_16x32 operator~() const { return SIMD_16x32(_mm512_xor_si512(m_avx512, _mm512_set1_epi32(0xFFFFFFFF))); }

      // (~reg) & other
      BOTAN_AVX512_FN
      SIMD_16x32 andc(const SIMD_16x32& other) const {
         return SIMD_16x32(_mm512_andnot_si512(m_avx512, other.m_avx512));
      }

      template <uint8_t TBL>
      BOTAN_AVX512_FN static SIMD_16x32 ternary_fn(const SIMD_16x32& a, const SIMD_16x32& b, const SIMD_16x32& c) {
         return _mm512_ternarylogic_epi32(a.raw(), b.raw(), c.raw(), TBL);
      }

      BOTAN_AVX512_FN
      SIMD_16x32 bswap() const {
         const uint8_t BSWAP_MASK[64] = {
            3,  2,  1,  0,  7,  6,  5,  4,  11, 10, 9,  8,  15, 14, 13, 12, 19, 18, 17, 16, 23, 22,
            21, 20, 27, 26, 25, 24, 31, 30, 29, 28, 35, 34, 33, 32, 39, 38, 37, 36, 43, 42, 41, 40,
            47, 46, 45, 44, 51, 50, 49, 48, 55, 54, 53, 52, 59, 58, 57, 56, 63, 62, 61, 60,
         };

         const __m512i bswap = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(BSWAP_MASK));

         const __m512i output = _mm512_shuffle_epi8(m_avx512, bswap);

         return SIMD_16x32(output);
      }

      BOTAN_AVX512_FN
      static void transpose(SIMD_16x32& B0, SIMD_16x32& B1, SIMD_16x32& B2, SIMD_16x32& B3) {
         const __m512i T0 = _mm512_unpacklo_epi32(B0.m_avx512, B1.m_avx512);
         const __m512i T1 = _mm512_unpacklo_epi32(B2.m_avx512, B3.m_avx512);
         const __m512i T2 = _mm512_unpackhi_epi32(B0.m_avx512, B1.m_avx512);
         const __m512i T3 = _mm512_unpackhi_epi32(B2.m_avx512, B3.m_avx512);

         B0.m_avx512 = _mm512_unpacklo_epi64(T0, T1);
         B1.m_avx512 = _mm512_unpackhi_epi64(T0, T1);
         B2.m_avx512 = _mm512_unpacklo_epi64(T2, T3);
         B3.m_avx512 = _mm512_unpackhi_epi64(T2, T3);
      }

      BOTAN_AVX512_FN
      static void transpose(SIMD_16x32& B0,
                            SIMD_16x32& B1,
                            SIMD_16x32& B2,
                            SIMD_16x32& B3,
                            SIMD_16x32& B4,
                            SIMD_16x32& B5,
                            SIMD_16x32& B6,
                            SIMD_16x32& B7,
                            SIMD_16x32& B8,
                            SIMD_16x32& B9,
                            SIMD_16x32& BA,
                            SIMD_16x32& BB,
                            SIMD_16x32& BC,
                            SIMD_16x32& BD,
                            SIMD_16x32& BE,
                            SIMD_16x32& BF) {
         auto t0 = _mm512_unpacklo_epi32(B0.raw(), B1.raw());
         auto t1 = _mm512_unpackhi_epi32(B0.raw(), B1.raw());
         auto t2 = _mm512_unpacklo_epi32(B2.raw(), B3.raw());
         auto t3 = _mm512_unpackhi_epi32(B2.raw(), B3.raw());
         auto t4 = _mm512_unpacklo_epi32(B4.raw(), B5.raw());
         auto t5 = _mm512_unpackhi_epi32(B4.raw(), B5.raw());
         auto t6 = _mm512_unpacklo_epi32(B6.raw(), B7.raw());
         auto t7 = _mm512_unpackhi_epi32(B6.raw(), B7.raw());
         auto t8 = _mm512_unpacklo_epi32(B8.raw(), B9.raw());
         auto t9 = _mm512_unpackhi_epi32(B8.raw(), B9.raw());
         auto ta = _mm512_unpacklo_epi32(BA.raw(), BB.raw());
         auto tb = _mm512_unpackhi_epi32(BA.raw(), BB.raw());
         auto tc = _mm512_unpacklo_epi32(BC.raw(), BD.raw());
         auto td = _mm512_unpackhi_epi32(BC.raw(), BD.raw());
         auto te = _mm512_unpacklo_epi32(BE.raw(), BF.raw());
         auto tf = _mm512_unpackhi_epi32(BE.raw(), BF.raw());

         auto r0 = _mm512_unpacklo_epi64(t0, t2);
         auto r1 = _mm512_unpackhi_epi64(t0, t2);
         auto r2 = _mm512_unpacklo_epi64(t1, t3);
         auto r3 = _mm512_unpackhi_epi64(t1, t3);
         auto r4 = _mm512_unpacklo_epi64(t4, t6);
         auto r5 = _mm512_unpackhi_epi64(t4, t6);
         auto r6 = _mm512_unpacklo_epi64(t5, t7);
         auto r7 = _mm512_unpackhi_epi64(t5, t7);
         auto r8 = _mm512_unpacklo_epi64(t8, ta);
         auto r9 = _mm512_unpackhi_epi64(t8, ta);
         auto ra = _mm512_unpacklo_epi64(t9, tb);
         auto rb = _mm512_unpackhi_epi64(t9, tb);
         auto rc = _mm512_unpacklo_epi64(tc, te);
         auto rd = _mm512_unpackhi_epi64(tc, te);
         auto re = _mm512_unpacklo_epi64(td, tf);
         auto rf = _mm512_unpackhi_epi64(td, tf);

         t0 = _mm512_shuffle_i32x4(r0, r4, 0x88);
         t1 = _mm512_shuffle_i32x4(r1, r5, 0x88);
         t2 = _mm512_shuffle_i32x4(r2, r6, 0x88);
         t3 = _mm512_shuffle_i32x4(r3, r7, 0x88);
         t4 = _mm512_shuffle_i32x4(r0, r4, 0xdd);
         t5 = _mm512_shuffle_i32x4(r1, r5, 0xdd);
         t6 = _mm512_shuffle_i32x4(r2, r6, 0xdd);
         t7 = _mm512_shuffle_i32x4(r3, r7, 0xdd);
         t8 = _mm512_shuffle_i32x4(r8, rc, 0x88);
         t9 = _mm512_shuffle_i32x4(r9, rd, 0x88);
         ta = _mm512_shuffle_i32x4(ra, re, 0x88);
         tb = _mm512_shuffle_i32x4(rb, rf, 0x88);
         tc = _mm512_shuffle_i32x4(r8, rc, 0xdd);
         td = _mm512_shuffle_i32x4(r9, rd, 0xdd);
         te = _mm512_shuffle_i32x4(ra, re, 0xdd);
         tf = _mm512_shuffle_i32x4(rb, rf, 0xdd);

         B0.m_avx512 = _mm512_shuffle_i32x4(t0, t8, 0x88);
         B1.m_avx512 = _mm512_shuffle_i32x4(t1, t9, 0x88);
         B2.m_avx512 = _mm512_shuffle_i32x4(t2, ta, 0x88);
         B3.m_avx512 = _mm512_shuffle_i32x4(t3, tb, 0x88);
         B4.m_avx512 = _mm512_shuffle_i32x4(t4, tc, 0x88);
         B5.m_avx512 = _mm512_shuffle_i32x4(t5, td, 0x88);
         B6.m_avx512 = _mm512_shuffle_i32x4(t6, te, 0x88);
         B7.m_avx512 = _mm512_shuffle_i32x4(t7, tf, 0x88);
         B8.m_avx512 = _mm512_shuffle_i32x4(t0, t8, 0xdd);
         B9.m_avx512 = _mm512_shuffle_i32x4(t1, t9, 0xdd);
         BA.m_avx512 = _mm512_shuffle_i32x4(t2, ta, 0xdd);
         BB.m_avx512 = _mm512_shuffle_i32x4(t3, tb, 0xdd);
         BC.m_avx512 = _mm512_shuffle_i32x4(t4, tc, 0xdd);
         BD.m_avx512 = _mm512_shuffle_i32x4(t5, td, 0xdd);
         BE.m_avx512 = _mm512_shuffle_i32x4(t6, te, 0xdd);
         BF.m_avx512 = _mm512_shuffle_i32x4(t7, tf, 0xdd);
      }

      BOTAN_AVX512_FN
      static SIMD_16x32 choose(const SIMD_16x32& mask, const SIMD_16x32& a, const SIMD_16x32& b) {
         return SIMD_16x32::ternary_fn<0xca>(mask, a, b);
      }

      BOTAN_AVX512_FN
      static SIMD_16x32 majority(const SIMD_16x32& x, const SIMD_16x32& y, const SIMD_16x32& z) {
         return SIMD_16x32::ternary_fn<0xe8>(x, y, z);
      }

      BOTAN_FUNC_ISA("avx2") static void zero_registers() {
         // Unfortunately this only zeros zmm0-zmm15 and not zmm16-zmm32
         _mm256_zeroall();
      }

      __m512i BOTAN_AVX512_FN raw() const { return m_avx512; }

      BOTAN_AVX512_FN
      SIMD_16x32(__m512i x) : m_avx512(x) {}

   private:
      __m512i m_avx512;
};

template <size_t R>
inline SIMD_16x32 rotl(SIMD_16x32 input) {
   return input.rotl<R>();
}

template <size_t R>
inline SIMD_16x32 rotr(SIMD_16x32 input) {
   return input.rotr<R>();
}

// For Serpent:
template <size_t S>
inline SIMD_16x32 shl(SIMD_16x32 input) {
   return input.shl<S>();
}

}  // namespace Botan

#endif
