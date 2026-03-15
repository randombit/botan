/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/idea.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/isa_extn.h>
#include <immintrin.h>

namespace Botan {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

/*
* SIMD type of 16 16-bit elements
*/
class SIMD_16x16 final {
   public:
      using native_type = __m256i;

      SIMD_16x16(const SIMD_16x16&) = default;
      SIMD_16x16& operator=(const SIMD_16x16&) = default;
      SIMD_16x16(SIMD_16x16&&) = default;
      SIMD_16x16& operator=(SIMD_16x16&&) = default;
      ~SIMD_16x16() = default;

      BOTAN_FN_ISA_AVX2 explicit SIMD_16x16(native_type x) : m_simd(x) {}

      static SIMD_16x16 BOTAN_FN_ISA_AVX2 load_le(const uint8_t in[]) {
         return SIMD_16x16(_mm256_loadu_si256(reinterpret_cast<const __m256i*>(in)));
      }

      void BOTAN_FN_ISA_AVX2 store_le(uint8_t out[]) const {
         _mm256_storeu_si256(reinterpret_cast<__m256i*>(out), m_simd);
      }

      static SIMD_16x16 BOTAN_FN_ISA_AVX2 load_be(const uint8_t in[]) { return load_le(in).bswap(); }

      void BOTAN_FN_ISA_AVX2 store_be(uint8_t out[]) const { bswap().store_le(out); }

      SIMD_16x16 BOTAN_FN_ISA_AVX2 bswap() const {
         // clang-format off
         const auto bswap_tbl = _mm256_set_epi8(
            14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1,
            14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1);
         // clang-format on
         return SIMD_16x16(_mm256_shuffle_epi8(m_simd, bswap_tbl));
      }

      SIMD_16x16 BOTAN_FN_ISA_AVX2 operator-(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_sub_epi16(m_simd, o.m_simd));
      }

      SIMD_16x16 BOTAN_FN_ISA_AVX2 operator^(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_xor_si256(m_simd, o.m_simd));
      }

      void BOTAN_FN_ISA_AVX2 operator+=(const SIMD_16x16& o) { m_simd = _mm256_add_epi16(m_simd, o.m_simd); }

      void BOTAN_FN_ISA_AVX2 operator+=(uint16_t v) { m_simd = _mm256_add_epi16(m_simd, _mm256_set1_epi16(v)); }

      void BOTAN_FN_ISA_AVX2 operator^=(const SIMD_16x16& o) { m_simd = _mm256_xor_si256(m_simd, o.m_simd); }

      static inline BOTAN_FN_ISA_AVX2 SIMD_16x16 mul_mod_65537(SIMD_16x16 X, uint16_t K_16) {
         const auto zeros = SIMD_16x16::splat(0);
         const auto ones = SIMD_16x16::splat(1);
         const auto K = SIMD_16x16::splat(K_16);

         // Each u16 of the output is set to all-1 mask if == 0, or otherwise 0
         const auto X_is_zero = SIMD_16x16(_mm256_cmpeq_epi16(X.raw(), zeros.raw()));
         const auto K_is_zero = SIMD_16x16(_mm256_cmpeq_epi16(K.raw(), zeros.raw()));

         const auto ml = SIMD_16x16(_mm256_mullo_epi16(X.raw(), K.raw()));
         const auto mh = SIMD_16x16(_mm256_mulhi_epu16(X.raw(), K.raw()));

         // AVX2 doesn't have unsigned comparisons for whatever dumb reason
         const auto bias = SIMD_16x16::splat(0x8000);
         const auto borrow = (mh ^ bias).cmpgt(ml ^ bias);

         // T = ml - mh + (mh > ml ? 1 : 0)
         auto T = ml - mh - borrow;

         // Set to 1-K or 1-X to handle the exceptional cases
         T = T.select_u16(ones - K, X_is_zero);
         T = T.select_u16(ones - X, K_is_zero);

         return T;
      }

      /*
      * 4x16 matrix transpose
      */
      static void BOTAN_FN_ISA_AVX2 transpose_in(SIMD_16x16& B0, SIMD_16x16& B1, SIMD_16x16& B2, SIMD_16x16& B3) {
         auto B0r = _mm256_shuffle_epi32(B0.raw(), _MM_SHUFFLE(3, 1, 2, 0));
         auto B1r = _mm256_shuffle_epi32(B1.raw(), _MM_SHUFFLE(3, 1, 2, 0));
         auto B2r = _mm256_shuffle_epi32(B2.raw(), _MM_SHUFFLE(3, 1, 2, 0));
         auto B3r = _mm256_shuffle_epi32(B3.raw(), _MM_SHUFFLE(3, 1, 2, 0));

         B0r = _mm256_shufflelo_epi16(B0r, _MM_SHUFFLE(3, 1, 2, 0));
         B1r = _mm256_shufflelo_epi16(B1r, _MM_SHUFFLE(3, 1, 2, 0));
         B2r = _mm256_shufflelo_epi16(B2r, _MM_SHUFFLE(3, 1, 2, 0));
         B3r = _mm256_shufflelo_epi16(B3r, _MM_SHUFFLE(3, 1, 2, 0));

         B0r = _mm256_shufflehi_epi16(B0r, _MM_SHUFFLE(3, 1, 2, 0));
         B1r = _mm256_shufflehi_epi16(B1r, _MM_SHUFFLE(3, 1, 2, 0));
         B2r = _mm256_shufflehi_epi16(B2r, _MM_SHUFFLE(3, 1, 2, 0));
         B3r = _mm256_shufflehi_epi16(B3r, _MM_SHUFFLE(3, 1, 2, 0));

         const auto T0 = _mm256_unpacklo_epi32(B0r, B1r);
         const auto T1 = _mm256_unpackhi_epi32(B0r, B1r);
         const auto T2 = _mm256_unpacklo_epi32(B2r, B3r);
         const auto T3 = _mm256_unpackhi_epi32(B2r, B3r);

         B0 = SIMD_16x16(_mm256_unpacklo_epi64(T0, T2));
         B1 = SIMD_16x16(_mm256_unpackhi_epi64(T0, T2));
         B2 = SIMD_16x16(_mm256_unpacklo_epi64(T1, T3));
         B3 = SIMD_16x16(_mm256_unpackhi_epi64(T1, T3));
      }

      /*
      * 4x16 matrix transpose (inverse)
      */
      static void BOTAN_FN_ISA_AVX2 transpose_out(SIMD_16x16& B0, SIMD_16x16& B1, SIMD_16x16& B2, SIMD_16x16& B3) {
         auto T0 = _mm256_unpacklo_epi64(B0.raw(), B1.raw());
         auto T1 = _mm256_unpacklo_epi64(B2.raw(), B3.raw());
         auto T2 = _mm256_unpackhi_epi64(B0.raw(), B1.raw());
         auto T3 = _mm256_unpackhi_epi64(B2.raw(), B3.raw());

         T0 = _mm256_shuffle_epi32(T0, _MM_SHUFFLE(3, 1, 2, 0));
         T1 = _mm256_shuffle_epi32(T1, _MM_SHUFFLE(3, 1, 2, 0));
         T2 = _mm256_shuffle_epi32(T2, _MM_SHUFFLE(3, 1, 2, 0));
         T3 = _mm256_shuffle_epi32(T3, _MM_SHUFFLE(3, 1, 2, 0));

         T0 = _mm256_shufflehi_epi16(T0, _MM_SHUFFLE(3, 1, 2, 0));
         T1 = _mm256_shufflehi_epi16(T1, _MM_SHUFFLE(3, 1, 2, 0));
         T2 = _mm256_shufflehi_epi16(T2, _MM_SHUFFLE(3, 1, 2, 0));
         T3 = _mm256_shufflehi_epi16(T3, _MM_SHUFFLE(3, 1, 2, 0));

         T0 = _mm256_shufflelo_epi16(T0, _MM_SHUFFLE(3, 1, 2, 0));
         T1 = _mm256_shufflelo_epi16(T1, _MM_SHUFFLE(3, 1, 2, 0));
         T2 = _mm256_shufflelo_epi16(T2, _MM_SHUFFLE(3, 1, 2, 0));
         T3 = _mm256_shufflelo_epi16(T3, _MM_SHUFFLE(3, 1, 2, 0));

         B0 = SIMD_16x16(_mm256_unpacklo_epi32(T0, T1));
         B1 = SIMD_16x16(_mm256_unpackhi_epi32(T0, T1));
         B2 = SIMD_16x16(_mm256_unpacklo_epi32(T2, T3));
         B3 = SIMD_16x16(_mm256_unpackhi_epi32(T2, T3));
      }

      native_type BOTAN_FN_ISA_AVX2 raw() const { return m_simd; }

   private:
      static SIMD_16x16 BOTAN_FN_ISA_AVX2 splat(uint16_t v) { return SIMD_16x16(_mm256_set1_epi16(v)); }

      SIMD_16x16 BOTAN_FN_ISA_AVX2 cmpgt(const SIMD_16x16& o) const {
         return SIMD_16x16(_mm256_cmpgt_epi16(m_simd, o.m_simd));
      }

      SIMD_16x16 BOTAN_FN_ISA_AVX2 select_u16(const SIMD_16x16& other, const SIMD_16x16& mask) const {
         return SIMD_16x16(_mm256_blendv_epi8(m_simd, other.m_simd, mask.m_simd));
      }

      native_type m_simd;
};

// NOLINTEND(portability-simd-intrinsics)

}  // namespace

BOTAN_FN_ISA_AVX2 void IDEA::avx2_idea_op_16(const uint8_t in[128], uint8_t out[128], const uint16_t EK[52]) {
   CT::poison(in, 128);
   CT::poison(out, 128);
   CT::poison(EK, 52);

   auto B0 = SIMD_16x16::load_be(in + 0);
   auto B1 = SIMD_16x16::load_be(in + 32);
   auto B2 = SIMD_16x16::load_be(in + 64);
   auto B3 = SIMD_16x16::load_be(in + 96);

   SIMD_16x16::transpose_in(B0, B1, B2, B3);

   for(size_t i = 0; i != 8; ++i) {
      B0 = SIMD_16x16::mul_mod_65537(B0, EK[6 * i + 0]);
      B1 += EK[6 * i + 1];
      B2 += EK[6 * i + 2];
      B3 = SIMD_16x16::mul_mod_65537(B3, EK[6 * i + 3]);

      const auto T0 = B2;
      B2 ^= B0;
      B2 = SIMD_16x16::mul_mod_65537(B2, EK[6 * i + 4]);

      const auto T1 = B1;

      B1 ^= B3;
      B1 += B2;
      B1 = SIMD_16x16::mul_mod_65537(B1, EK[6 * i + 5]);

      B2 += B1;

      B0 ^= B1;
      B1 ^= T0;
      B3 ^= B2;
      B2 ^= T1;
   }

   B0 = SIMD_16x16::mul_mod_65537(B0, EK[48]);
   B1 += EK[50];
   B2 += EK[49];
   B3 = SIMD_16x16::mul_mod_65537(B3, EK[51]);

   SIMD_16x16::transpose_out(B0, B2, B1, B3);

   B0.store_be(out + 0);
   B2.store_be(out + 32);
   B1.store_be(out + 64);
   B3.store_be(out + 96);

   CT::unpoison(in, 128);
   CT::unpoison(out, 128);
   CT::unpoison(EK, 52);
}

}  // namespace Botan
