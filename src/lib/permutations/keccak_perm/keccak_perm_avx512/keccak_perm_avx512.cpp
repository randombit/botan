/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/keccak_perm.h>

#include <botan/internal/isa_extn.h>
#include <immintrin.h>

namespace Botan {

namespace {

class SIMD_5x64 final {
   public:
      explicit BOTAN_FN_ISA_AVX512 SIMD_5x64() : SIMD_5x64(_mm512_setzero_si512()) {}

      static BOTAN_FN_ISA_AVX512 SIMD_5x64 rc(uint64_t RC) {
         return SIMD_5x64(_mm512_maskz_set1_epi64(0b00000001, RC));
      }

      static BOTAN_FN_ISA_AVX512 SIMD_5x64 load(const uint64_t v[5]) {
         return SIMD_5x64(_mm512_maskz_loadu_epi64(0b00011111, v));
      }

      template <size_t I0, size_t I1, size_t I2, size_t I3, size_t I4>
      inline BOTAN_FN_ISA_AVX512 SIMD_5x64 permute() const {
         static_assert(I0 < 5 && I1 < 5 && I2 < 5 && I3 < 5 && I4 < 5);
         const __m512i tbl = _mm512_setr_epi64(I0, I1, I2, I3, I4, 0, 0, 0);
         return SIMD_5x64(_mm512_permutexvar_epi64(tbl, m_v));
      }

      static BOTAN_FN_ISA_AVX512 void transpose5(
         SIMD_5x64& i0, SIMD_5x64& i1, SIMD_5x64& i2, SIMD_5x64& i3, SIMD_5x64& i4) {
         // 5x5 u64 transpose using 7 permutex2var, 4 unpack, 1 blend, 5 constants

         const auto lo_01 = _mm512_unpacklo_epi64(i0.m_v, i1.m_v);
         const auto lo_23 = _mm512_unpacklo_epi64(i2.m_v, i3.m_v);

         const auto hi_01 = _mm512_unpackhi_epi64(i0.m_v, i1.m_v);
         const auto hi_23 = _mm512_unpackhi_epi64(i2.m_v, i3.m_v);

         // Insert the relevant words from i4 into the i0/i1 data
         const auto i4_lo_idx = _mm512_setr_epi64(0, 1, 2, 3, 4, 5, 8, 10);
         const auto i4_hi_idx = _mm512_setr_epi64(0, 1, 2, 3, -1, -1, 9, 11);

         auto t0 = _mm512_permutex2var_epi64(lo_01, i4_lo_idx, i4.m_v);
         auto t2 = _mm512_permutex2var_epi64(hi_01, i4_hi_idx, i4.m_v);

         // Now merge the 0/1/4 and 2/3 vectors using permutes
         const auto idx0 = _mm512_setr_epi64(0, 1, 8, 9, 6, -1, -1, -1);
         const auto idx1 = _mm512_setr_epi64(2, 3, 10, 11, 7, -1, -1, -1);
         const auto idx4 = _mm512_setr_epi64(4, 5, 12, 13, -1, -1, -1, -1);

         i0.m_v = _mm512_permutex2var_epi64(t0, idx0, lo_23);
         i1.m_v = _mm512_permutex2var_epi64(t2, idx0, hi_23);
         i2.m_v = _mm512_permutex2var_epi64(t0, idx1, lo_23);
         i3.m_v = _mm512_permutex2var_epi64(t2, idx1, hi_23);
         i4.m_v = _mm512_mask_blend_epi64(0b00010000, _mm512_permutex2var_epi64(t0, idx4, lo_23), i4.m_v);
      }

      static BOTAN_FN_ISA_AVX512 SIMD_5x64 chi(const SIMD_5x64& x, const SIMD_5x64& y, const SIMD_5x64& z) {
         constexpr uint8_t xor_not_and = 0b11010010;  // (x ^ (~y & z))
         return SIMD_5x64(_mm512_ternarylogic_epi64(x.m_v, y.m_v, z.m_v, xor_not_and));
      }

      friend BOTAN_FN_ISA_AVX512 SIMD_5x64 operator^(const SIMD_5x64& x, const SIMD_5x64& y) {
         return SIMD_5x64(_mm512_xor_epi64(x.m_v, y.m_v));
      }

      static BOTAN_FN_ISA_AVX512 SIMD_5x64
      xor5(const SIMD_5x64& i0, const SIMD_5x64& i1, const SIMD_5x64& i2, const SIMD_5x64& i3, const SIMD_5x64& i4) {
         constexpr uint8_t tern_xor = 0b10010110;
         auto t = _mm512_ternarylogic_epi64(i0.m_v, i1.m_v, i2.m_v, tern_xor);
         return SIMD_5x64(_mm512_ternarylogic_epi64(i3.m_v, i4.m_v, t, tern_xor));
      }

      BOTAN_FN_ISA_AVX512 SIMD_5x64 rol1() const { return SIMD_5x64(_mm512_rol_epi64(m_v, 1)); }

      template <size_t R0, size_t R1, size_t R2, size_t R3, size_t R4>
      BOTAN_FN_ISA_AVX512 SIMD_5x64 rolv() const {
         static_assert(R0 < 64 && R1 < 64 && R2 < 64 && R3 < 64 && R4 < 64);
         const __m512i rot = _mm512_setr_epi64(R0, R1, R2, R3, R4, 0, 0, 0);
         return SIMD_5x64(_mm512_rolv_epi64(m_v, rot));
      }

      BOTAN_FN_ISA_AVX512 void store(uint64_t v[5]) const { _mm512_mask_storeu_epi64(v, 0b00011111, m_v); }

   private:
      explicit BOTAN_FN_ISA_AVX512 SIMD_5x64(__m512i v) : m_v(v) {}

      __m512i m_v;
};

inline void BOTAN_FN_ISA_AVX512 Keccak_Permutation_round_avx512(SIMD_5x64 A[5], uint64_t RC) {
   const auto C = SIMD_5x64::xor5(A[0], A[1], A[2], A[3], A[4]);

   const auto D = C.permute<4, 0, 1, 2, 3>() ^ C.permute<1, 2, 3, 4, 0>().rol1();

   const auto B0 = (A[0] ^ D).permute<0, 3, 1, 4, 2>().rolv<0, 28, 1, 27, 62>();
   const auto B1 = (A[1] ^ D).permute<1, 4, 2, 0, 3>().rolv<44, 20, 6, 36, 55>();
   const auto B2 = (A[2] ^ D).permute<2, 0, 3, 1, 4>().rolv<43, 3, 25, 10, 39>();
   const auto B3 = (A[3] ^ D).permute<3, 1, 4, 2, 0>().rolv<21, 45, 8, 15, 41>();
   const auto B4 = (A[4] ^ D).permute<4, 2, 0, 3, 1>().rolv<14, 61, 18, 56, 2>();

   auto T0 = SIMD_5x64::chi(B0, B1, B2) ^ SIMD_5x64::rc(RC);
   auto T1 = SIMD_5x64::chi(B1, B2, B3);
   auto T2 = SIMD_5x64::chi(B2, B3, B4);
   auto T3 = SIMD_5x64::chi(B3, B4, B0);
   auto T4 = SIMD_5x64::chi(B4, B0, B1);

   SIMD_5x64::transpose5(T0, T1, T2, T3, T4);

   A[0] = T0;
   A[1] = T1;
   A[2] = T2;
   A[3] = T3;
   A[4] = T4;
}

}  // namespace

void BOTAN_FN_ISA_AVX512 Keccak_Permutation::permute_avx512() {
   static const uint64_t RC[24] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                                   0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                                   0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                                   0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                                   0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                                   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

   auto& S = state();

   std::array<SIMD_5x64, 5> X{
      SIMD_5x64::load(&S[0]),  // NOLINT(*container-data-pointer)
      SIMD_5x64::load(&S[5]),
      SIMD_5x64::load(&S[10]),
      SIMD_5x64::load(&S[15]),
      SIMD_5x64::load(&S[20]),
   };

   // NOLINTNEXTLINE(modernize-loop-convert)
   for(size_t i = 0; i != 24; ++i) {
      Keccak_Permutation_round_avx512(X.data(), RC[i]);
   }

   for(size_t i = 0; i != 5; ++i) {
      X[i].store(&S[5 * i]);
   }
}

}  // namespace Botan
