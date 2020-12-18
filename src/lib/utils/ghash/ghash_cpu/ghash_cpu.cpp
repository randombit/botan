/*
* Hook for CLMUL/PMULL/VPMSUM
* (C) 2013,2017,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ghash.h>
#include <botan/internal/simd_32.h>

#if defined(BOTAN_SIMD_USE_SSE2)
  #include <immintrin.h>
  #include <wmmintrin.h>
#endif

namespace Botan {

namespace {

BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FUNC_ISA(BOTAN_VPERM_ISA) reverse_vector(const SIMD_4x32& in)
   {
#if defined(BOTAN_SIMD_USE_SSE2)
   const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
   return SIMD_4x32(_mm_shuffle_epi8(in.raw(), BSWAP_MASK));
#elif defined(BOTAN_SIMD_USE_NEON)
   const uint8_t maskb[16] = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
   const uint8x16_t mask = vld1q_u8(maskb);
   return SIMD_4x32(vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(in.raw()), mask)));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
   const __vector unsigned char mask = {15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0};
   return SIMD_4x32(vec_perm(in.raw(), in.raw(), mask));
#endif
   }

template<int M>
BOTAN_FORCE_INLINE SIMD_4x32 BOTAN_FUNC_ISA(BOTAN_CLMUL_ISA) clmul(const SIMD_4x32& H, const SIMD_4x32& x)
   {
   static_assert(M == 0x00 || M == 0x01 || M == 0x10 || M == 0x11, "Valid clmul mode");

#if defined(BOTAN_SIMD_USE_SSE2)
   return SIMD_4x32(_mm_clmulepi64_si128(x.raw(), H.raw(), M));
#elif defined(BOTAN_SIMD_USE_NEON)
   const uint64_t a = vgetq_lane_u64(vreinterpretq_u64_u32(x.raw()), M & 0x01);
   const uint64_t b = vgetq_lane_u64(vreinterpretq_u64_u32(H.raw()), (M & 0x10) >> 4);
   return SIMD_4x32(reinterpret_cast<uint32x4_t>(vmull_p64(a, b)));
#elif defined(BOTAN_SIMD_USE_ALTIVEC)
   const SIMD_4x32 mask_lo = SIMD_4x32(0, 0, 0xFFFFFFFF, 0xFFFFFFFF);

   SIMD_4x32 i1 = x;
   SIMD_4x32 i2 = H;

   if(M == 0x11)
      {
      i1 &= mask_lo;
      i2 &= mask_lo;
      }
   else if(M == 0x10)
      {
      i1 = i1.shift_elems_left<2>();
      }
   else if(M == 0x01)
      {
      i2 = i2.shift_elems_left<2>();
      }
   else if(M == 0x00)
      {
      i1 = mask_lo.andc(i1);
      i2 = mask_lo.andc(i2);
      }

   auto i1v = reinterpret_cast<__vector unsigned long long>(i1.raw());
   auto i2v = reinterpret_cast<__vector unsigned long long>(i2.raw());

#if defined(__clang__)
   auto rv = __builtin_altivec_crypto_vpmsumd(i1v, i2v);
#else
   auto rv = __builtin_crypto_vpmsumd(i1v, i2v);
#endif

   return SIMD_4x32(reinterpret_cast<__vector unsigned int>(rv));
#endif
   }

inline SIMD_4x32 gcm_reduce(const SIMD_4x32& B0, const SIMD_4x32& B1)
   {
   SIMD_4x32 X0 = B1.shr<31>();
   SIMD_4x32 X1 = B1.shl<1>();
   SIMD_4x32 X2 = B0.shr<31>();
   SIMD_4x32 X3 = B0.shl<1>();

   X3 |= X0.shift_elems_right<3>();
   X3 |= X2.shift_elems_left<1>();
   X1 |= X0.shift_elems_left<1>();

   X0 = X1.shl<31>() ^ X1.shl<30>() ^ X1.shl<25>();

   X1 ^= X0.shift_elems_left<3>();

   X0 = X1 ^ X3 ^ X0.shift_elems_right<1>();
   X0 ^= X1.shr<7>() ^ X1.shr<2>() ^ X1.shr<1>();
   return X0;
   }

inline SIMD_4x32 BOTAN_FUNC_ISA(BOTAN_CLMUL_ISA) gcm_multiply(const SIMD_4x32& H, const SIMD_4x32& x)
   {
   SIMD_4x32 T0 = clmul<0x11>(H, x);
   SIMD_4x32 T1 = clmul<0x10>(H, x);
   SIMD_4x32 T2 = clmul<0x01>(H, x);
   SIMD_4x32 T3 = clmul<0x00>(H, x);

   T1 ^= T2;
   T0 ^= T1.shift_elems_right<2>();
   T3 ^= T1.shift_elems_left<2>();

   return gcm_reduce(T0, T3);
   }

inline SIMD_4x32 BOTAN_FUNC_ISA(BOTAN_CLMUL_ISA)
   gcm_multiply_x4(const SIMD_4x32& H1, const SIMD_4x32& H2, const SIMD_4x32& H3, const SIMD_4x32& H4,
                   const SIMD_4x32& X1, const SIMD_4x32& X2, const SIMD_4x32& X3, const SIMD_4x32& X4)
   {
   /*
   * Mutiply with delayed reduction, algorithm by Krzysztof Jankowski
   * and Pierre Laurent of Intel
   */

   const SIMD_4x32 lo = (clmul<0x00>(H1, X1) ^ clmul<0x00>(H2, X2)) ^
                        (clmul<0x00>(H3, X3) ^ clmul<0x00>(H4, X4));

   const SIMD_4x32 hi = (clmul<0x11>(H1, X1) ^ clmul<0x11>(H2, X2)) ^
                        (clmul<0x11>(H3, X3) ^ clmul<0x11>(H4, X4));

   SIMD_4x32 T;

   T ^= clmul<0x00>(H1 ^ H1.shift_elems_right<2>(), X1 ^ X1.shift_elems_right<2>());
   T ^= clmul<0x00>(H2 ^ H2.shift_elems_right<2>(), X2 ^ X2.shift_elems_right<2>());
   T ^= clmul<0x00>(H3 ^ H3.shift_elems_right<2>(), X3 ^ X3.shift_elems_right<2>());
   T ^= clmul<0x00>(H4 ^ H4.shift_elems_right<2>(), X4 ^ X4.shift_elems_right<2>());
   T ^= lo;
   T ^= hi;

   return gcm_reduce(hi ^ T.shift_elems_right<2>(),
                     lo ^ T.shift_elems_left<2>());
   }

}

BOTAN_FUNC_ISA(BOTAN_VPERM_ISA)
void GHASH::ghash_precompute_cpu(const uint8_t H_bytes[16], uint64_t H_pow[4*2])
   {
   const SIMD_4x32 H1 = reverse_vector(SIMD_4x32::load_le(H_bytes));
   const SIMD_4x32 H2 = gcm_multiply(H1, H1);
   const SIMD_4x32 H3 = gcm_multiply(H1, H2);
   const SIMD_4x32 H4 = gcm_multiply(H2, H2);

   H1.store_le(H_pow);
   H2.store_le(H_pow + 2);
   H3.store_le(H_pow + 4);
   H4.store_le(H_pow + 6);
   }

BOTAN_FUNC_ISA(BOTAN_VPERM_ISA)
void GHASH::ghash_multiply_cpu(uint8_t x[16],
                               const uint64_t H_pow[8],
                               const uint8_t input[], size_t blocks)
   {
   /*
   * Algorithms 1 and 5 from Intel's CLMUL guide
   */
   const SIMD_4x32 H1 = SIMD_4x32::load_le(H_pow);

   SIMD_4x32 a = reverse_vector(SIMD_4x32::load_le(x));

   if(blocks >= 4)
      {
      const SIMD_4x32 H2 = SIMD_4x32::load_le(H_pow + 2);
      const SIMD_4x32 H3 = SIMD_4x32::load_le(H_pow + 4);
      const SIMD_4x32 H4 = SIMD_4x32::load_le(H_pow + 6);

      while(blocks >= 4)
         {
         const SIMD_4x32 m0 = reverse_vector(SIMD_4x32::load_le(input       ));
         const SIMD_4x32 m1 = reverse_vector(SIMD_4x32::load_le(input + 16*1));
         const SIMD_4x32 m2 = reverse_vector(SIMD_4x32::load_le(input + 16*2));
         const SIMD_4x32 m3 = reverse_vector(SIMD_4x32::load_le(input + 16*3));

         a ^= m0;
         a = gcm_multiply_x4(H1, H2, H3, H4, m3, m2, m1, a);

         input += 4*16;
         blocks -= 4;
         }
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      const SIMD_4x32 m = reverse_vector(SIMD_4x32::load_le(input + 16*i));

      a ^= m;
      a = gcm_multiply(H1, a);
      }

   a = reverse_vector(a);
   a.store_le(x);
   }

}
