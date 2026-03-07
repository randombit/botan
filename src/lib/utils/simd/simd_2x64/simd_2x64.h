/*
* (C) 2022,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_2X64_H_
#define BOTAN_SIMD_2X64_H_

#include <botan/compiler.h>
#include <botan/types.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/target_info.h>
#include <span>

// TODO: extend this to support NEON / AltiVec / LSX

#if defined(BOTAN_TARGET_ARCH_SUPPORTS_SSSE3)
   #include <tmmintrin.h>
   #define BOTAN_SIMD_USE_SSSE3
#elif defined(BOTAN_TARGET_ARCH_SUPPORTS_SIMD128)
   #include <wasm_simd128.h>
   #define BOTAN_SIMD_USE_SIMD128
#endif

namespace Botan {

// NOLINTBEGIN(portability-simd-intrinsics)

class SIMD_2x64 final {
   public:
#if defined(BOTAN_SIMD_USE_SSSE3)
      using native_simd_type = __m128i;
#elif defined(BOTAN_SIMD_USE_SIMD128)
      using native_simd_type = v128_t;
#endif

      SIMD_2x64& operator=(const SIMD_2x64& other) = default;
      SIMD_2x64(const SIMD_2x64& other) = default;

      SIMD_2x64& operator=(SIMD_2x64&& other) = default;
      SIMD_2x64(SIMD_2x64&& other) = default;

      ~SIMD_2x64() = default;

      // zero initialized
      BOTAN_FN_ISA_SIMD_2X64 SIMD_2x64() :
#if defined(BOTAN_SIMD_USE_SSSE3)
            m_simd(_mm_setzero_si128())
#elif defined(BOTAN_SIMD_USE_SIMD128)
            m_simd(wasm_u64x2_const_splat(0))
#endif
      {
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 all_ones() {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_set1_epi8(-1));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_i8x16_splat(0xFF));
#endif
      }

      BOTAN_FN_ISA_SIMD_2X64 SIMD_2x64(uint64_t low, uint64_t high) :
#if defined(BOTAN_SIMD_USE_SSSE3)
            m_simd(_mm_set_epi64x(high, low))
#elif defined(BOTAN_SIMD_USE_SIMD128)
            m_simd(wasm_u64x2_make(low, high))
#endif
      {
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 load_le(const void* in) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_loadu_si128(reinterpret_cast<const __m128i*>(in)));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_v128_load(in));
#endif
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 load_be(const void* in) { return SIMD_2x64::load_le(in).bswap(); }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 load_le(std::span<const uint8_t, 16> in) {
         return SIMD_2x64::load_le(in.data());
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 load_be(std::span<const uint8_t, 16> in) {
         return SIMD_2x64::load_be(in.data());
      }

      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 bswap() const {
#if defined(BOTAN_SIMD_USE_SSSE3)
         const auto idx = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
         return SIMD_2x64(_mm_shuffle_epi8(m_simd, idx));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_i8x16_shuffle(m_simd, m_simd, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8));
#endif
      }

      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 swap_lanes() const {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_shuffle_epi32(m_simd, _MM_SHUFFLE(1, 0, 3, 2)));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_i64x2_shuffle(m_simd, m_simd, 1, 0));
#endif
      }

      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 reverse_all_bytes() const {
#if defined(BOTAN_SIMD_USE_SSSE3)
         const auto idx = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
         return SIMD_2x64(_mm_shuffle_epi8(m_simd, idx));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_i8x16_shuffle(m_simd, m_simd, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
#endif
      }

      void BOTAN_FN_ISA_SIMD_2X64 store_le(uint64_t out[2]) const { this->store_le(reinterpret_cast<uint8_t*>(out)); }

      void BOTAN_FN_ISA_SIMD_2X64 store_le(uint8_t out[]) const {
#if defined(BOTAN_SIMD_USE_SSSE3)
         _mm_storeu_si128(reinterpret_cast<__m128i*>(out), m_simd);
#elif defined(BOTAN_SIMD_USE_SIMD128)
         wasm_v128_store(out, m_simd);
#endif
      }

      void BOTAN_FN_ISA_SIMD_2X64 store_be(uint64_t out[2]) const { this->store_be(reinterpret_cast<uint8_t*>(out)); }

      void BOTAN_FN_ISA_SIMD_2X64 store_be(uint8_t out[]) const { bswap().store_le(out); }

      void BOTAN_FN_ISA_SIMD_2X64 store_be(std::span<uint8_t, 16> out) const { this->store_be(out.data()); }

      void BOTAN_FN_ISA_SIMD_2X64 store_le(std::span<uint8_t, 16> out) const { this->store_le(out.data()); }

      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 operator+(const SIMD_2x64& other) const {
         SIMD_2x64 retval(*this);
         retval += other;
         return retval;
      }

      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 operator^(const SIMD_2x64& other) const {
         SIMD_2x64 retval(*this);
         retval ^= other;
         return retval;
      }

      void BOTAN_FN_ISA_SIMD_2X64 operator+=(const SIMD_2x64& other) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_add_epi64(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_SIMD128)
         m_simd = wasm_i64x2_add(m_simd, other.m_simd);
#endif
      }

      void BOTAN_FN_ISA_SIMD_2X64 operator^=(const SIMD_2x64& other) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         m_simd = _mm_xor_si128(m_simd, other.m_simd);
#elif defined(BOTAN_SIMD_USE_SIMD128)
         m_simd = wasm_v128_xor(m_simd, other.m_simd);
#endif
      }

      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 andc(const SIMD_2x64& other) const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_andnot_si128(m_simd, other.m_simd));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         // SIMD128 is a & ~b
         return SIMD_2x64(wasm_v128_andnot(other.m_simd, m_simd));
#endif
      }

      template <size_t ROT>
      BOTAN_FN_ISA_SIMD_2X64 SIMD_2x64 rotr() const
         requires(ROT > 0 && ROT < 64)
      {
#if defined(BOTAN_SIMD_USE_SSSE3)
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
#elif defined(BOTAN_SIMD_USE_SIMD128)
         if constexpr(ROT == 8) {
            return SIMD_2x64(wasm_i8x16_shuffle(m_simd, m_simd, 1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8));
         } else if constexpr(ROT == 16) {
            return SIMD_2x64(wasm_i8x16_shuffle(m_simd, m_simd, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9));
         } else if constexpr(ROT == 24) {
            return SIMD_2x64(wasm_i8x16_shuffle(m_simd, m_simd, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10));
         } else if constexpr(ROT == 32) {
            return SIMD_2x64(wasm_i8x16_shuffle(m_simd, m_simd, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11));
         } else {
            return SIMD_2x64(wasm_v128_or(wasm_u64x2_shr(m_simd, ROT), wasm_i64x2_shl(m_simd, 64 - ROT)));
         }
#endif
      }

      template <size_t ROT>
      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 rotl() const {
         return this->rotr<64 - ROT>();
      }

      template <int SHIFT>
      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 shr() const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_srli_epi64(m_simd, SHIFT));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_u64x2_shr(m_simd, SHIFT));
#endif
      }

      template <int SHIFT>
      SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 shl() const noexcept {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_slli_epi64(m_simd, SHIFT));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_i64x2_shl(m_simd, SHIFT));
#endif
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 alignr8(const SIMD_2x64& a, const SIMD_2x64& b) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_alignr_epi8(a.m_simd, b.m_simd, 8));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(
            wasm_i8x16_shuffle(b.m_simd, a.m_simd, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23));
#endif
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 interleave_low(const SIMD_2x64& a, const SIMD_2x64& b) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_unpacklo_epi64(a.m_simd, b.m_simd));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_u64x2_extract_lane(a.m_simd, 0), wasm_u64x2_extract_lane(b.m_simd, 0));
#endif
      }

      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 interleave_high(const SIMD_2x64& a, const SIMD_2x64& b) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         return SIMD_2x64(_mm_unpackhi_epi64(a.m_simd, b.m_simd));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         return SIMD_2x64(wasm_u64x2_extract_lane(a.m_simd, 1), wasm_u64x2_extract_lane(b.m_simd, 1));
#endif
      }

      // Argon2 specific operation
      static void BOTAN_FN_ISA_SIMD_2X64
      twist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         auto T0 = SIMD_2x64::alignr8(B1, B0);
         auto T1 = SIMD_2x64::alignr8(B0, B1);
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
      static void BOTAN_FN_ISA_SIMD_2X64
      untwist(SIMD_2x64& B0, SIMD_2x64& B1, SIMD_2x64& C0, SIMD_2x64& C1, SIMD_2x64& D0, SIMD_2x64& D1) {
         auto T0 = SIMD_2x64::alignr8(B0, B1);
         auto T1 = SIMD_2x64::alignr8(B1, B0);
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
      static SIMD_2x64 BOTAN_FN_ISA_SIMD_2X64 mul2_32(SIMD_2x64 x, SIMD_2x64 y) {
#if defined(BOTAN_SIMD_USE_SSSE3)
         const __m128i m = _mm_mul_epu32(x.m_simd, y.m_simd);
         return SIMD_2x64(_mm_add_epi64(m, m));
#elif defined(BOTAN_SIMD_USE_SIMD128)
         const auto m = wasm_u64x2_extmul_low_u32x4(wasm_i32x4_shuffle(x.m_simd, x.m_simd, 0, 2, 0, 2),
                                                    wasm_i32x4_shuffle(y.m_simd, y.m_simd, 0, 2, 0, 2));

         return SIMD_2x64(wasm_i64x2_add(m, m));
#endif
      }

      native_simd_type BOTAN_FN_ISA_SIMD_2X64 raw() const noexcept { return m_simd; }

      explicit BOTAN_FN_ISA_SIMD_2X64 SIMD_2x64(native_simd_type x) : m_simd(x) {}

   private:
      native_simd_type m_simd;
};

// NOLINTEND(portability-simd-intrinsics)

}  // namespace Botan

#endif
