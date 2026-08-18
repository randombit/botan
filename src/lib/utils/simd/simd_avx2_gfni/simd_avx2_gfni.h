/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_AVX2_GFNI_H_
#define BOTAN_SIMD_AVX2_GFNI_H_

#include <botan/internal/simd_8x32.h>

#include <botan/internal/gfni_utils.h>
#include <botan/internal/isa_extn.h>

namespace Botan {

template <uint64_t A, uint8_t B>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_GFNI SIMD_8x32 gf2p8affine(const SIMD_8x32& x) {
   return SIMD_8x32(_mm256_gf2p8affine_epi64_epi8(x.raw(), _mm256_set1_epi64x(A), B));
}

template <uint64_t A, uint8_t B>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_GFNI SIMD_8x32 gf2p8affineinv(const SIMD_8x32& x) {
   return SIMD_8x32(_mm256_gf2p8affineinv_epi64_epi8(x.raw(), _mm256_set1_epi64x(A), B));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_GFNI SIMD_8x32 gf2p8mul(const SIMD_8x32& a, const SIMD_8x32& b) {
   return SIMD_8x32(_mm256_gf2p8mul_epi8(a.raw(), b.raw()));
}

}  // namespace Botan

#endif
