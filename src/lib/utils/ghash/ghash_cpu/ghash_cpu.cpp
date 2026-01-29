/*
* Hook for CLMUL/PMULL/VPMSUM
* (C) 2013,2017,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ghash.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/polyval_fn.h>
#include <botan/internal/simd_4x32.h>

namespace Botan {

namespace {

inline SIMD_4x32 BOTAN_FN_ISA_CLMUL polyval_multiply_x4(const SIMD_4x32& H1,
                                                        const SIMD_4x32& H2,
                                                        const SIMD_4x32& H3,
                                                        const SIMD_4x32& H4,
                                                        const SIMD_4x32& X1,
                                                        const SIMD_4x32& X2,
                                                        const SIMD_4x32& X3,
                                                        const SIMD_4x32& X4) {
   const SIMD_4x32 lo = (clmul<0x00>(H1, X1) ^ clmul<0x00>(H2, X2)) ^ (clmul<0x00>(H3, X3) ^ clmul<0x00>(H4, X4));
   const SIMD_4x32 hi = (clmul<0x11>(H1, X1) ^ clmul<0x11>(H2, X2)) ^ (clmul<0x11>(H3, X3) ^ clmul<0x11>(H4, X4));

   SIMD_4x32 mid;

   mid ^= clmul<0x00>(H1 ^ H1.shift_elems_right<2>(), X1 ^ X1.shift_elems_right<2>());
   mid ^= clmul<0x00>(H2 ^ H2.shift_elems_right<2>(), X2 ^ X2.shift_elems_right<2>());
   mid ^= clmul<0x00>(H3 ^ H3.shift_elems_right<2>(), X3 ^ X3.shift_elems_right<2>());
   mid ^= clmul<0x00>(H4 ^ H4.shift_elems_right<2>(), X4 ^ X4.shift_elems_right<2>());
   mid ^= lo;
   mid ^= hi;

   return polyval_reduce(hi ^ mid.shift_elems_right<2>(), lo ^ mid.shift_elems_left<2>());
}

}  // namespace

void BOTAN_FN_ISA_CLMUL GHASH::ghash_precompute_cpu(const uint8_t H_bytes[16], uint64_t H_pow[4 * 2]) {
   const SIMD_4x32 H1 = mulx_polyval(reverse_vector(SIMD_4x32::load_le(H_bytes)));
   const SIMD_4x32 H2 = polyval_multiply(H1, H1);
   const SIMD_4x32 H3 = polyval_multiply(H1, H2);
   const SIMD_4x32 H4 = polyval_multiply(H2, H2);

   H1.store_le(H_pow);
   H2.store_le(H_pow + 2);
   H3.store_le(H_pow + 4);
   H4.store_le(H_pow + 6);
}

void BOTAN_FN_ISA_CLMUL GHASH::ghash_multiply_cpu(uint8_t x[16],
                                                  const uint64_t H_pow[8],
                                                  const uint8_t input[],
                                                  size_t blocks) {
   /*
   * Algorithms 1 and 5 from Intel's CLMUL guide
   */
   const SIMD_4x32 H1 = SIMD_4x32::load_le(H_pow);

   SIMD_4x32 a = reverse_vector(SIMD_4x32::load_le(x));

   if(blocks >= 4) {
      const SIMD_4x32 H2 = SIMD_4x32::load_le(H_pow + 2);
      const SIMD_4x32 H3 = SIMD_4x32::load_le(H_pow + 4);
      const SIMD_4x32 H4 = SIMD_4x32::load_le(H_pow + 6);

      while(blocks >= 4) {
         const SIMD_4x32 m0 = reverse_vector(SIMD_4x32::load_le(input));
         const SIMD_4x32 m1 = reverse_vector(SIMD_4x32::load_le(input + 16 * 1));
         const SIMD_4x32 m2 = reverse_vector(SIMD_4x32::load_le(input + 16 * 2));
         const SIMD_4x32 m3 = reverse_vector(SIMD_4x32::load_le(input + 16 * 3));

         a ^= m0;
         a = polyval_multiply_x4(H1, H2, H3, H4, m3, m2, m1, a);

         input += 4 * 16;
         blocks -= 4;
      }
   }

   for(size_t i = 0; i != blocks; ++i) {
      const SIMD_4x32 m = reverse_vector(SIMD_4x32::load_le(input + 16 * i));

      a ^= m;
      a = polyval_multiply(H1, a);
   }

   a = reverse_vector(a);
   a.store_le(x);
}

}  // namespace Botan
