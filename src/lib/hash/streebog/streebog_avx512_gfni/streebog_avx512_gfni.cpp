/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/streebog.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/streebog_const.h>
#include <array>
#include <immintrin.h>

namespace Botan {

namespace {

consteval std::array<std::array<uint64_t, 8>, 8> streebog_avx512_affine_table() {
   auto gfni_mul_matrix = [](uint8_t c) -> uint64_t {
      uint64_t q = 0;
      for(size_t r = 0; r != 8; ++r) {
         const size_t out_bit = 7 - r;
         uint8_t byte_r = 0;
         for(size_t b = 0; b != 8; ++b) {
            const uint8_t prod = poly_mul<0x1D>(static_cast<uint8_t>(1U << b), c);  // c * alpha^b
            if(((prod >> out_bit) & 1) != 0) {
               byte_r |= static_cast<uint8_t>(1U << b);
            }
         }
         q |= static_cast<uint64_t>(byte_r) << (8 * r);
      }
      return q;
   };

   std::array<std::array<uint64_t, 8>, 8> tbl = {};
   for(size_t j = 0; j != 8; ++j) {
      for(size_t k = 0; k != 8; ++k) {
         tbl[j][k] = gfni_mul_matrix(static_cast<uint8_t>(STREEBOG_L[j] >> (8 * k)));
      }
   }
   return tbl;
}

alignas(256) constexpr auto STREEBOG_AVX512_AFFINE = streebog_avx512_affine_table();

consteval std::array<uint8_t, 64> streebog_transpose_idx() {
   std::array<uint8_t, 64> idx = {};
   for(size_t i = 0; i != 8; ++i) {
      for(size_t k = 0; k != 8; ++k) {
         idx[8 * i + k] = static_cast<uint8_t>(8 * k + i);
      }
   }
   return idx;
}

BOTAN_FN_ISA_AVX512_GFNI BOTAN_FORCE_INLINE __m512i streebog_sbox(__m512i x) {
   // Load the constant tables
   const __m512i S0 = _mm512_loadu_si512(&STREEBOG_S[0]);
   const __m512i S1 = _mm512_loadu_si512(&STREEBOG_S[64]);
   const __m512i S2 = _mm512_loadu_si512(&STREEBOG_S[128]);
   const __m512i S3 = _mm512_loadu_si512(&STREEBOG_S[192]);

   // Select from both halves then blend
   const __m512i lo = _mm512_permutex2var_epi8(S0, x, S1);
   const __m512i hi = _mm512_permutex2var_epi8(S2, x, S3);
   const __mmask64 m = _mm512_movepi8_mask(x);
   return _mm512_mask_blend_epi8(m, lo, hi);
}

BOTAN_FN_ISA_AVX512_GFNI BOTAN_FORCE_INLINE __m512i streebog_lps(__m512i x) {
   alignas(64) constexpr auto STREEBOG_TIDX = streebog_transpose_idx();

   const __m512i sx = streebog_sbox(x);
   __m512i mt = _mm512_setzero_si512();
   for(size_t i = 0; i != 8; ++i) {
      const __m512i idx = _mm512_set1_epi64(static_cast<long long>(i));
      const __m512i ci = _mm512_loadu_si512(STREEBOG_AVX512_AFFINE[i].data());
      mt = _mm512_xor_si512(mt, _mm512_gf2p8affine_epi64_epi8(_mm512_permutexvar_epi64(idx, sx), ci, 0));
   }
   return _mm512_permutexvar_epi8(_mm512_loadu_si512(STREEBOG_TIDX.data()), mt);
}

BOTAN_FN_ISA_AVX512_GFNI BOTAN_FORCE_INLINE void streebog_lps_x2(__m512i& a, __m512i& b) {
   alignas(64) constexpr auto STREEBOG_TIDX = streebog_transpose_idx();

   const __m512i sa = streebog_sbox(a);
   const __m512i sb = streebog_sbox(b);
   __m512i ma = _mm512_setzero_si512();
   __m512i mb = _mm512_setzero_si512();
   for(size_t i = 0; i != 8; ++i) {
      const __m512i idx = _mm512_set1_epi64(static_cast<long long>(i));
      const __m512i ci = _mm512_loadu_si512(STREEBOG_AVX512_AFFINE[i].data());
      ma = _mm512_xor_si512(ma, _mm512_gf2p8affine_epi64_epi8(_mm512_permutexvar_epi64(idx, sa), ci, 0));
      mb = _mm512_xor_si512(mb, _mm512_gf2p8affine_epi64_epi8(_mm512_permutexvar_epi64(idx, sb), ci, 0));
   }
   const __m512i tidx = _mm512_loadu_si512(STREEBOG_TIDX.data());
   a = _mm512_permutexvar_epi8(tidx, ma);
   b = _mm512_permutexvar_epi8(tidx, mb);
}

}  // namespace

void BOTAN_FN_ISA_AVX512_GFNI Streebog::compress_64_avx512_gfni(uint64_t h[8], const uint64_t M[8], uint64_t N) {
   auto streebog_rc_table = []() consteval -> std::array<std::array<uint64_t, 8>, 12> {
      std::array<std::array<uint64_t, 8>, 12> tbl = {};
      for(size_t i = 0; i != 12; ++i) {
         for(size_t j = 0; j != 8; ++j) {
            tbl[i][j] = STREEBOG_C[i][7 - j];
         }
      }
      return tbl;
   };

   alignas(64) constexpr auto STREEBOG_RC = streebog_rc_table();

   const __m512i hv = _mm512_loadu_si512(h);
   const __m512i mv = _mm512_loadu_si512(M);

   __m512i hN = streebog_lps(_mm512_xor_si512(hv, _mm512_maskz_set1_epi64(0x01, static_cast<long long>(N))));
   __m512i a = hN;
   hN = _mm512_xor_si512(hN, mv);

   for(size_t i = 0; i != 12; ++i) {
      a = _mm512_xor_si512(a, _mm512_loadu_si512(STREEBOG_RC[i].data()));
      streebog_lps_x2(a, hN);
      hN = _mm512_xor_si512(hN, a);
   }

   _mm512_storeu_si512(h, _mm512_xor_si512(_mm512_xor_si512(hv, hN), mv));
}

}  // namespace Botan
