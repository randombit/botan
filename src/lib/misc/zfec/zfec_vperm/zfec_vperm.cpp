/*
* (C) 2011 Billy Brumley (billy.brumley@aalto.fi)
* (C) 2021,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/zfec.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <array>

namespace Botan {

namespace {

/*
 * these tables are for the linear map bx^4 + a -> y(bx^4 + a)
 * implemented as two maps:
 * a -> y(a)
 * b -> y(bx^4)
 * and the final output is the sum of these two outputs.
 */
consteval std::array<uint8_t, 256 * 32> zfec_vperm_table() {
   std::array<uint8_t, 256 * 32> tbl = {};

   for(size_t y = 0; y != 256; ++y) {
      for(size_t i = 0; i != 16; ++i) {
         tbl[32 * y + i] = poly_mul<0x1D>(static_cast<uint8_t>(i), static_cast<uint8_t>(y));
         tbl[32 * y + 16 + i] = poly_mul<0x1D>(static_cast<uint8_t>(i << 4), static_cast<uint8_t>(y));
      }
   }

   return tbl;
}

alignas(256) constexpr auto GFTBL = zfec_vperm_table();

/*
* One pass of z[] = [z[] +] x[0][] * y[0] + ... + x[N-1][] * y[N-1]
*/
template <size_t N>
BOTAN_FN_ISA_SIMD_4X32 void vperm_linear_combination_pass(
   uint8_t z[], const uint8_t* const x[], const uint8_t y[], bool accum, size_t size) {
   const auto mask = SIMD_4x32::splat_u8(0x0F);

   SIMD_4x32 t_lo[N];
   SIMD_4x32 t_hi[N];
   for(size_t t = 0; t != N; ++t) {
      t_lo[t] = SIMD_4x32::load_le(GFTBL.data() + 32 * y[t]);
      t_hi[t] = SIMD_4x32::load_le(GFTBL.data() + 32 * y[t] + 16);
   }

   size_t off = 0;
   while(off + 16 <= size) {
      auto acc = accum ? SIMD_4x32::load_le(z + off) : SIMD_4x32();

      for(size_t t = 0; t != N; ++t) {
         const auto x_t = SIMD_4x32::load_le(x[t] + off);

         // mask to get LO nibble for LO LUT input
         const auto x_lo = x_t & mask;
         // mask to get HI nibble for HI LUT input
         const auto x_hi = x_t.shr<4>() & mask;

         // 16x parallel lookups, summing the outputs
         acc ^= SIMD_4x32::byte_shuffle(t_lo[t], x_lo);
         acc ^= SIMD_4x32::byte_shuffle(t_hi[t], x_hi);
      }

      acc.store_le(z + off);
      off += 16;
   }
}

}  // namespace

BOTAN_FN_ISA_SIMD_4X32 size_t
ZFEC::linear_combination_vperm(uint8_t z[], const uint8_t* const x[], const uint8_t y[], size_t k, size_t size) {
   const size_t blocks = size - (size % 16);

   if(blocks == 0) {
      return 0;
   }

   size_t j = 0;
   while(j + 4 <= k) {
      vperm_linear_combination_pass<4>(z, x + j, y + j, j > 0, blocks);
      j += 4;
   }
   if(j + 2 <= k) {
      vperm_linear_combination_pass<2>(z, x + j, y + j, j > 0, blocks);
      j += 2;
   }
   if(j < k) {
      vperm_linear_combination_pass<1>(z, x + j, y + j, j > 0, blocks);
   }

   return blocks;
}

}  // namespace Botan
