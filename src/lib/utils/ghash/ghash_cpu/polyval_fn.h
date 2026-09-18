/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_POLYVAL_FN_H_
#define BOTAN_POLYVAL_FN_H_

#include <botan/internal/simd_4x32.h>

#if defined(BOTAN_SIMD_USE_SSSE3)
   #include <wmmintrin.h>
#endif

namespace Botan {

// NOLINTBEGIN(portability-simd-intrinsics)

template <int M>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_CLMUL SIMD_4x32 clmul(const SIMD_4x32& H, const SIMD_4x32& x) {
   static_assert(M == 0x00 || M == 0x01 || M == 0x10 || M == 0x11, "Valid clmul mode");

#if defined(BOTAN_SIMD_USE_SSSE3)
   return SIMD_4x32(_mm_clmulepi64_si128(x.raw(), H.raw(), M));
#elif defined(BOTAN_SIMD_USE_NEON)
   const uint64_t a = vgetq_lane_u64(vreinterpretq_u64_u32(x.raw()), M & 0x01);
   const uint64_t b = vgetq_lane_u64(vreinterpretq_u64_u32(H.raw()), (M & 0x10) >> 4);

   #if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   __n64 a1 = {a}, b1 = {b};
   return SIMD_4x32(vmull_p64(a1, b1));
   #else
   return SIMD_4x32(reinterpret_cast<uint32x4_t>(vmull_p64(a, b)));
   #endif

#elif defined(BOTAN_SIMD_USE_ALTIVEC)
   const SIMD_4x32 mask_lo = SIMD_4x32(0, 0, 0xFFFFFFFF, 0xFFFFFFFF);
   constexpr uint8_t flip = (std::endian::native == std::endian::big) ? 0x11 : 0x00;

   SIMD_4x32 i1 = x;
   SIMD_4x32 i2 = H;

   if constexpr(std::endian::native == std::endian::big) {
      i1 = i1.reverse_all_bytes().bswap();
      i2 = i2.reverse_all_bytes().bswap();
   }

   if constexpr(M == (0x11 ^ flip)) {
      i1 &= mask_lo;
      i2 &= mask_lo;
   } else if constexpr(M == (0x10 ^ flip)) {
      i1 = i1.shift_elems_left<2>();
   } else if constexpr(M == (0x01 ^ flip)) {
      i2 = i2.shift_elems_left<2>();
   } else if constexpr(M == (0x00 ^ flip)) {
      i1 = mask_lo.andc(i1);
      i2 = mask_lo.andc(i2);
   }

   auto i1v = reinterpret_cast<__vector unsigned long long>(i1.raw());
   auto i2v = reinterpret_cast<__vector unsigned long long>(i2.raw());

   #if BOTAN_COMPILER_HAS_BUILTIN(__builtin_crypto_vpmsumd)
   auto rv = __builtin_crypto_vpmsumd(i1v, i2v);
   #else
   auto rv = __builtin_altivec_crypto_vpmsumd(i1v, i2v);
   #endif

   auto z = SIMD_4x32(reinterpret_cast<__vector unsigned int>(rv));

   if constexpr(std::endian::native == std::endian::big) {
      z = z.reverse_all_bytes().bswap();
   }

   return z;
#endif
}

// NOLINTEND(portability-simd-intrinsics)

/**
* Load a block in the reflected GHASH convention (BSWAP == true) or the
* natural POLYVAL convention (BSWAP == false)
*/
template <bool BSWAP>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_SIMD_4X32 SIMD_4x32 load_block(const uint8_t in[]) {
   if constexpr(BSWAP) {
      return SIMD_4x32::load_le(in).reverse_all_bytes();
   } else {
      return SIMD_4x32::load_le(in);
   }
}

template <bool BSWAP>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_SIMD_4X32 void store_block(const SIMD_4x32& b, uint8_t out[]) {
   if constexpr(BSWAP) {
      b.reverse_all_bytes().store_le(out);
   } else {
      b.store_le(out);
   }
}

BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FN_ISA_SIMD_4X32 mulx_polyval(const SIMD_4x32& h) {
   const auto V = SIMD_4x32(0x00000001, 0x00000000, 0x00000000, 0xc2000000);

   // Bitmask set iff the top bit of h is set
   const auto mask = h.top_bit_mask();

   // Extract the top bits of the words and move them into place as the low bit of the next word
   auto top_bits = h.shr<31>().shift_elems_left<1>();

   // The main shift, adding back in the top bits that are otherwise lost
   auto shifted_h = h.shl<1>() | top_bits;

   return shifted_h ^ (mask & V);
}

BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FN_ISA_CLMUL polyval_reduce(const SIMD_4x32& hi, const SIMD_4x32& lo) {
   const SIMD_4x32 V(0, 0xC2000000, 0, 0);

   /*
   Montgomery reduction
   Input: 256-bit operand [X3 : X2 : X1 : X0]
   [A1 : A0] = X0 * 0xc200000000000000
   [B1 : B0] = [X0 + A1 : X1 + A0]
   [C1 : C0] = B0 * 0xc200000000000000
   [D1 : D0] = [B0 + C1 : B1 + C0]
   Output: [D1 + X3 : D0 + X2]
   */

   const auto A = clmul<0x00>(lo, V);
   const auto B = A ^ lo.swap_halves();
   const auto C = clmul<0x00>(B, V);
   const auto D = C ^ B.swap_halves();

   return D ^ hi;
}

BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FN_ISA_CLMUL polyval_multiply(const SIMD_4x32& H, const SIMD_4x32& x) {
   SIMD_4x32 hi = clmul<0x11>(H, x);
   const SIMD_4x32 mid = clmul<0x10>(H, x) ^ clmul<0x01>(H, x);
   SIMD_4x32 lo = clmul<0x00>(H, x);

   hi ^= mid.shift_elems_right<2>();
   lo ^= mid.shift_elems_left<2>();

   return polyval_reduce(hi, lo);
}

}  // namespace Botan

#endif
