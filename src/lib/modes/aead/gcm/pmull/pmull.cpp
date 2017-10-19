/*
* Contributed by Jeffrey Walton
*
* Further changes
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pmull.h>
#include <arm_neon.h>

namespace Botan {

/*
This follows the same pattern as the clmul implementation.

See also http://conradoplg.cryptoland.net/files/2010/12/gcm14.pdf
*/

namespace {

BOTAN_FUNC_ISA("+simd")
inline uint64x2_t gcm_reduce(uint32x4_t B0, uint32x4_t B1)
   {
   const uint32x4_t zero = vdupq_n_u32(0);

   uint32x4_t T0, T1, T2, T3, T4, T5;

   T4 = vshrq_n_u32(B0, 31);
   T0 = vshlq_n_u32(B0, 1);
   T5 = vshrq_n_u32(B1, 31);
   T3 = vshlq_n_u32(B1, 1);

   T2 = vextq_u32(T4, zero, 3);
   T5 = vextq_u32(zero, T5, 3);
   T4 = vextq_u32(zero, T4, 3);
   T0 = vorrq_u32(T0, T4);
   T3 = vorrq_u32(T3, T5);
   T3 = vorrq_u32(T3, T2);

   T4 = vshlq_n_u32(T0, 31);
   T5 = vshlq_n_u32(T0, 30);
   T2 = vshlq_n_u32(T0, 25);

   T4 = veorq_u32(T4, T5);
   T4 = veorq_u32(T4, T2);
   T5 = vextq_u32(T4, zero, 1);
   T3 = veorq_u32(T3, T5);
   T4 = vextq_u32(zero, T4, 1);
   T0 = veorq_u32(T0, T4);
   T3 = veorq_u32(T3, T0);

   T4 = vshrq_n_u32(T0, 1);
   T1 = vshrq_n_u32(T0, 2);
   T2 = vshrq_n_u32(T0, 7);
   T3 = veorq_u32(T3, T1);
   T3 = veorq_u32(T3, T2);
   T3 = veorq_u32(T3, T4);

   return vreinterpretq_u64_u32(T3);
   }

BOTAN_FUNC_ISA("+crypto")
inline uint64x2_t gcm_multiply(uint64x2_t H, uint64x2_t x)
   {
   const uint32x4_t zero = vdupq_n_u32(0);

   const uint64_t x_hi = vgetq_lane_u64(x, 0);
   const uint64_t x_lo = vgetq_lane_u64(x, 1);
   const uint64_t H_hi = vgetq_lane_u64(H, 0);
   const uint64_t H_lo = vgetq_lane_u64(H, 1);

   uint32x4_t T0 = (uint32x4_t)vmull_p64(x_hi, H_hi);
   uint32x4_t T1 = (uint32x4_t)vmull_p64(x_lo, H_hi);
   uint32x4_t T2 = (uint32x4_t)vmull_p64(x_hi, H_lo);
   uint32x4_t T3 = (uint32x4_t)vmull_p64(x_lo, H_lo);

   T1 = veorq_u32(T1, T2);
   T0 = veorq_u32(T0, vextq_u32(zero, T1, 2));
   T3 = veorq_u32(T3, vextq_u32(T1, zero, 2));

   return gcm_reduce(T0, T3);
   }

BOTAN_FUNC_ISA("+crypto")
inline uint64x2_t gcm_multiply_x4(uint64x2_t H1, uint64x2_t H2, uint64x2_t H3, uint64x2_t H4,
                                  uint64x2_t X1, uint64x2_t X2, uint64x2_t X3, uint64x2_t X4)
   {
   const uint64_t H1_hi = vgetq_lane_u64(H1, 0);
   const uint64_t H1_lo = vgetq_lane_u64(H1, 1);
   const uint64_t H2_hi = vgetq_lane_u64(H2, 0);
   const uint64_t H2_lo = vgetq_lane_u64(H2, 1);
   const uint64_t H3_hi = vgetq_lane_u64(H3, 0);
   const uint64_t H3_lo = vgetq_lane_u64(H3, 1);
   const uint64_t H4_hi = vgetq_lane_u64(H4, 0);
   const uint64_t H4_lo = vgetq_lane_u64(H4, 1);

   const uint64_t X1_hi = vgetq_lane_u64(X1, 0);
   const uint64_t X1_lo = vgetq_lane_u64(X1, 1);
   const uint64_t X2_hi = vgetq_lane_u64(X2, 0);
   const uint64_t X2_lo = vgetq_lane_u64(X2, 1);
   const uint64_t X3_hi = vgetq_lane_u64(X3, 0);
   const uint64_t X3_lo = vgetq_lane_u64(X3, 1);
   const uint64_t X4_hi = vgetq_lane_u64(X4, 0);
   const uint64_t X4_lo = vgetq_lane_u64(X4, 1);

   const uint32x4_t H1_X1_lo = (uint32x4_t)vmull_p64(X1_lo, H1_lo);
   const uint32x4_t H2_X2_lo = (uint32x4_t)vmull_p64(X2_lo, H2_lo);
   const uint32x4_t H3_X3_lo = (uint32x4_t)vmull_p64(X3_lo, H3_lo);
   const uint32x4_t H4_X4_lo = (uint32x4_t)vmull_p64(X4_lo, H4_lo);

   const uint32x4_t lo = veorq_u32(
      veorq_u32(H1_X1_lo, H2_X2_lo),
      veorq_u32(H3_X3_lo, H4_X4_lo));

   const uint32x4_t H1_X1_hi = (uint32x4_t)vmull_p64(X1_hi, H1_hi);
   const uint32x4_t H2_X2_hi = (uint32x4_t)vmull_p64(X2_hi, H2_hi);
   const uint32x4_t H3_X3_hi = (uint32x4_t)vmull_p64(X3_hi, H3_hi);
   const uint32x4_t H4_X4_hi = (uint32x4_t)vmull_p64(X4_hi, H4_hi);

   const uint32x4_t hi = veorq_u32(
      veorq_u32(H1_X1_hi, H2_X2_hi),
      veorq_u32(H3_X3_hi, H4_X4_hi));

   uint32x4_t T0 = veorq_u32(lo, hi);

   T0 = veorq_u32(T0, (uint32x4_t)vmull_p64(X1_hi ^ X1_lo, H1_hi ^ H1_lo));
   T0 = veorq_u32(T0, (uint32x4_t)vmull_p64(X2_hi ^ X2_lo, H2_hi ^ H2_lo));
   T0 = veorq_u32(T0, (uint32x4_t)vmull_p64(X3_hi ^ X3_lo, H3_hi ^ H3_lo));
   T0 = veorq_u32(T0, (uint32x4_t)vmull_p64(X4_hi ^ X4_lo, H4_hi ^ H4_lo));

   const uint32x4_t zero = vdupq_n_u32(0);
   uint32x4_t B0 = veorq_u32(vextq_u32(zero, T0, 2), hi);
   uint32x4_t B1 = veorq_u32(vextq_u32(T0, zero, 2), lo);
   return gcm_reduce(B0, B1);
   }

BOTAN_FUNC_ISA("+simd")
inline uint8x16_t bswap_vec(uint8x16_t v)
   {
   const uint8_t maskb[16] = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
   const uint8x16_t mask = vld1q_u8(maskb);
   return vqtbl1q_u8(v, mask);
   }

}

BOTAN_FUNC_ISA("+simd")
void gcm_pmull_precompute(const uint8_t H_bytes[16], uint64_t H_pow[4*2])
   {
   const uint64x2_t H = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(H_bytes)));
   const uint64x2_t H2 = gcm_multiply(H, H);
   const uint64x2_t H3 = gcm_multiply(H, H2);
   const uint64x2_t H4 = gcm_multiply(H, H3);

   vst1q_u64(H_pow  , H);
   vst1q_u64(H_pow+2, H2);
   vst1q_u64(H_pow+4, H3);
   vst1q_u64(H_pow+6, H4);
   }

BOTAN_FUNC_ISA("+simd")
void gcm_multiply_pmull(uint8_t x[16],
                        const uint64_t H64[8],
                        const uint8_t input[], size_t blocks)
   {
   const uint64x2_t H = vld1q_u64(H64);
   uint64x2_t a = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(x)));

   if(blocks >= 4)
      {
      const uint64x2_t H2 = vld1q_u64(H64 + 2);
      const uint64x2_t H3 = vld1q_u64(H64 + 4);
      const uint64x2_t H4 = vld1q_u64(H64 + 6);

      while(blocks >= 4)
         {
         const uint64x2_t m0 = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(input)));
         const uint64x2_t m1 = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(input + 16)));
         const uint64x2_t m2 = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(input + 32)));
         const uint64x2_t m3 = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(input + 48)));

         a = veorq_u64(a, m0);
         a = gcm_multiply_x4(H, H2, H3, H4, m3, m2, m1, a);

         input += 64;
         blocks -= 4;
         }
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      const uint64x2_t m = vreinterpretq_u64_u8(bswap_vec(vld1q_u8(input + 16*i)));
      a = veorq_u64(a, m);
      a = gcm_multiply(H, a);
      }

   vst1q_u8(x, bswap_vec(vreinterpretq_u8_u64(a)));
   }

}
