/*
* (C) 2017 Jack Lloyd
* (C) 2025 polarnis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ghash.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_2x64.h>

namespace Botan {

BOTAN_FN_ISA_SIMD_2X64
void GHASH::ghash_multiply_vperm(uint8_t x[16], const uint64_t HM[256], const uint8_t input_bytes[], size_t blocks) {
   auto X = SIMD_2x64::load_le(x).reverse_all_bytes();

   const auto* HM_mm = reinterpret_cast<const SIMD_2x64::native_simd_type*>(HM);
   const auto ones = SIMD_2x64::all_ones();

   for(size_t b = 0; b != blocks; ++b) {
      const auto M = SIMD_2x64::load_le(input_bytes + b * 16).reverse_all_bytes();
      X ^= M;

      SIMD_2x64 Z = {};

      for(size_t i = 0; i != 64; i += 2) {
         const auto HM0 = SIMD_2x64::load_le(HM_mm + 2 * i);
         const auto HM1 = SIMD_2x64::load_le(HM_mm + 2 * i + 1);
         const auto HM2 = SIMD_2x64::load_le(HM_mm + 2 * i + 2);
         const auto HM3 = SIMD_2x64::load_le(HM_mm + 2 * i + 3);

         const auto XMASK1 = X.shr<63>() + ones;
         X = X.shl<1>();
         const auto XMASK2 = X.shr<63>() + ones;
         X = X.shl<1>();

         Z ^= SIMD_2x64::interleave_high(XMASK1, XMASK1).andc(HM0);
         Z ^= SIMD_2x64::interleave_low(XMASK1, XMASK1).andc(HM1);
         Z ^= SIMD_2x64::interleave_high(XMASK2, XMASK2).andc(HM2);
         Z ^= SIMD_2x64::interleave_low(XMASK2, XMASK2).andc(HM3);
      }

      X = Z.swap_lanes();
   }

   X.reverse_all_bytes().store_le(x);
}

}  // namespace Botan
