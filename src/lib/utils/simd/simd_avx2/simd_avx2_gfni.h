/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_AVX2_GFNI_H_
#define BOTAN_SIMD_AVX2_GFNI_H_

#include <botan/internal/simd_avx2.h>

namespace Botan {

#define BOTAN_GFNI_ISA "gfni,avx2"

template <uint8_t B>
BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA)
SIMD_8x32 gf2p8affine(const SIMD_8x32& x, const SIMD_8x32& a) {
   return SIMD_8x32(_mm256_gf2p8affine_epi64_epi8(x.raw(), a.raw(), B));
}

template <uint8_t B>
BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA)
SIMD_8x32 gf2p8affineinv(const SIMD_8x32& x, const SIMD_8x32& a) {
   return SIMD_8x32(_mm256_gf2p8affineinv_epi64_epi8(x.raw(), a.raw(), B));
}

BOTAN_FUNC_ISA_INLINE(BOTAN_GFNI_ISA) SIMD_8x32 gf2p8mul(const SIMD_8x32& a, const SIMD_8x32& b) {
   return SIMD_8x32(_mm256_gf2p8mul_epi8(a.raw(), b.raw()));
}

}  // namespace Botan

#endif
