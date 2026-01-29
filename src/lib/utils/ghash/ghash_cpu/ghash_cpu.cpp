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

inline SIMD_4x32 BOTAN_FN_ISA_CLMUL polyval_multiply_x8(const SIMD_4x32& H1,
                                                        const SIMD_4x32& H2,
                                                        const SIMD_4x32& H3,
                                                        const SIMD_4x32& H4,
                                                        const SIMD_4x32& H5,
                                                        const SIMD_4x32& H6,
                                                        const SIMD_4x32& H7,
                                                        const SIMD_4x32& H8,
                                                        const SIMD_4x32& X1,
                                                        const SIMD_4x32& X2,
                                                        const SIMD_4x32& X3,
                                                        const SIMD_4x32& X4,
                                                        const SIMD_4x32& X5,
                                                        const SIMD_4x32& X6,
                                                        const SIMD_4x32& X7,
                                                        const SIMD_4x32& X8) {
   const SIMD_4x32 lo = clmul<0x00>(H1, X1) ^ clmul<0x00>(H2, X2) ^ clmul<0x00>(H3, X3) ^ clmul<0x00>(H4, X4) ^
                        clmul<0x00>(H5, X5) ^ clmul<0x00>(H6, X6) ^ clmul<0x00>(H7, X7) ^ clmul<0x00>(H8, X8);

   const SIMD_4x32 hi = clmul<0x11>(H1, X1) ^ clmul<0x11>(H2, X2) ^ clmul<0x11>(H3, X3) ^ clmul<0x11>(H4, X4) ^
                        clmul<0x11>(H5, X5) ^ clmul<0x11>(H6, X6) ^ clmul<0x11>(H7, X7) ^ clmul<0x11>(H8, X8);

   SIMD_4x32 mid;

   mid ^= clmul<0x00>(H1 ^ H1.shift_elems_right<2>(), X1 ^ X1.shift_elems_right<2>());
   mid ^= clmul<0x00>(H2 ^ H2.shift_elems_right<2>(), X2 ^ X2.shift_elems_right<2>());
   mid ^= clmul<0x00>(H3 ^ H3.shift_elems_right<2>(), X3 ^ X3.shift_elems_right<2>());
   mid ^= clmul<0x00>(H4 ^ H4.shift_elems_right<2>(), X4 ^ X4.shift_elems_right<2>());
   mid ^= clmul<0x00>(H5 ^ H5.shift_elems_right<2>(), X5 ^ X5.shift_elems_right<2>());
   mid ^= clmul<0x00>(H6 ^ H6.shift_elems_right<2>(), X6 ^ X6.shift_elems_right<2>());
   mid ^= clmul<0x00>(H7 ^ H7.shift_elems_right<2>(), X7 ^ X7.shift_elems_right<2>());
   mid ^= clmul<0x00>(H8 ^ H8.shift_elems_right<2>(), X8 ^ X8.shift_elems_right<2>());
   mid ^= lo;
   mid ^= hi;

   return polyval_reduce(hi ^ mid.shift_elems_right<2>(), lo ^ mid.shift_elems_left<2>());
}

}  // namespace

void BOTAN_FN_ISA_CLMUL GHASH::ghash_precompute_cpu(const uint8_t H_bytes[16], uint64_t H_pow[8 * 2]) {
   const SIMD_4x32 H1 = mulx_polyval(reverse_vector(SIMD_4x32::load_le(H_bytes)));
   const SIMD_4x32 H2 = polyval_multiply(H1, H1);
   const SIMD_4x32 H3 = polyval_multiply(H1, H2);
   const SIMD_4x32 H4 = polyval_multiply(H2, H2);
   const SIMD_4x32 H5 = polyval_multiply(H4, H1);
   const SIMD_4x32 H6 = polyval_multiply(H4, H2);
   const SIMD_4x32 H7 = polyval_multiply(H4, H3);
   const SIMD_4x32 H8 = polyval_multiply(H4, H4);

   H1.store_le(H_pow);
   H2.store_le(H_pow + 2);
   H3.store_le(H_pow + 4);
   H4.store_le(H_pow + 6);
   H5.store_le(H_pow + 8);
   H6.store_le(H_pow + 10);
   H7.store_le(H_pow + 12);
   H8.store_le(H_pow + 14);
}

void BOTAN_FN_ISA_CLMUL GHASH::ghash_multiply_cpu(uint8_t x[16],
                                                  const uint64_t H_pow[16],
                                                  const uint8_t input[],
                                                  size_t blocks) {
   const SIMD_4x32 H1 = SIMD_4x32::load_le(H_pow);

   SIMD_4x32 a = reverse_vector(SIMD_4x32::load_le(x));

   if(blocks >= 8) {
      const SIMD_4x32 H2 = SIMD_4x32::load_le(H_pow + 2);
      const SIMD_4x32 H3 = SIMD_4x32::load_le(H_pow + 4);
      const SIMD_4x32 H4 = SIMD_4x32::load_le(H_pow + 6);
      const SIMD_4x32 H5 = SIMD_4x32::load_le(H_pow + 8);
      const SIMD_4x32 H6 = SIMD_4x32::load_le(H_pow + 10);
      const SIMD_4x32 H7 = SIMD_4x32::load_le(H_pow + 12);
      const SIMD_4x32 H8 = SIMD_4x32::load_le(H_pow + 14);

      while(blocks >= 8) {
         const SIMD_4x32 m0 = reverse_vector(SIMD_4x32::load_le(input));
         const SIMD_4x32 m1 = reverse_vector(SIMD_4x32::load_le(input + 16 * 1));
         const SIMD_4x32 m2 = reverse_vector(SIMD_4x32::load_le(input + 16 * 2));
         const SIMD_4x32 m3 = reverse_vector(SIMD_4x32::load_le(input + 16 * 3));
         const SIMD_4x32 m4 = reverse_vector(SIMD_4x32::load_le(input + 16 * 4));
         const SIMD_4x32 m5 = reverse_vector(SIMD_4x32::load_le(input + 16 * 5));
         const SIMD_4x32 m6 = reverse_vector(SIMD_4x32::load_le(input + 16 * 6));
         const SIMD_4x32 m7 = reverse_vector(SIMD_4x32::load_le(input + 16 * 7));

         a = polyval_multiply_x8(H1, H2, H3, H4, H5, H6, H7, H8, m7, m6, m5, m4, m3, m2, m1, m0 ^ a);

         input += 8 * 16;
         blocks -= 8;
      }
   }

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
