/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_AVX2_GFNI_H_
#define BOTAN_SIMD_AVX2_GFNI_H_

#include <botan/internal/simd_avx2.h>
#include <stdexcept>
#include <string_view>

namespace Botan {

#define BOTAN_GFNI_ISA "gfni,avx2"

// Helper for defining GFNI constants
consteval uint64_t gfni_matrix(std::string_view s) {
   uint64_t matrix = 0;
   size_t bit_cnt = 0;
   uint8_t row = 0;

   for(char c : s) {
      if(c == ' ' || c == '\n') {
         continue;
      }
      if(c != '0' && c != '1') {
         throw std::runtime_error("gfni_matrix: invalid bit value");
      }

      if(c == '1') {
         row |= 0x80 >> (7 - bit_cnt % 8);
      }
      bit_cnt++;

      if(bit_cnt % 8 == 0) {
         matrix <<= 8;
         matrix |= row;
         row = 0;
      }
   }

   if(bit_cnt != 64) {
      throw std::runtime_error("gfni_matrix: invalid bit count");
   }

   return matrix;
}

template <uint64_t A, uint8_t B>
BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA)
SIMD_8x32 gf2p8affine(const SIMD_8x32& x) {
   return SIMD_8x32(_mm256_gf2p8affine_epi64_epi8(x.raw(), _mm256_set1_epi64x(A), B));
}

template <uint64_t A, uint8_t B>
BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA)
SIMD_8x32 gf2p8affineinv(const SIMD_8x32& x) {
   return SIMD_8x32(_mm256_gf2p8affineinv_epi64_epi8(x.raw(), _mm256_set1_epi64x(A), B));
}

BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA) SIMD_8x32 gf2p8mul(const SIMD_8x32& a, const SIMD_8x32& b) {
   return SIMD_8x32(_mm256_gf2p8mul_epi8(a.raw(), b.raw()));
}

}  // namespace Botan

#endif
