/*
* Contributed by Jeffrey Walton
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pmull.h>
#include <arm_neon.h>

namespace Botan {

BOTAN_FUNC_ISA("+crypto")
void gcm_multiply_pmull(uint8_t x[16], const uint8_t H[16])
   {
   /*
   * Implementing GCM on ARMv8, http://conradoplg.cryptoland.net/files/2010/12/gcm14.pdf
   */

   const uint64x2_t a64 = vreinterpretq_u64_u8(vcombine_u8(vrev64_u8(vld1_u8(x+8)), vrev64_u8(vld1_u8(x))));
   const uint64x2_t b64 = vreinterpretq_u64_u8(vcombine_u8(vrev64_u8(vld1_u8(H+8)), vrev64_u8(vld1_u8(H))));

   uint64x2_t T0, T1, T2, T3, T4, T5;

   T0 = (uint64x2_t)vmull_p64(vgetq_lane_u64(a64, 0), vgetq_lane_u64(b64, 0));
   T1 = (uint64x2_t)vmull_p64(vgetq_lane_u64(a64, 1), vgetq_lane_u64(b64, 0));
   T2 = (uint64x2_t)vmull_p64(vgetq_lane_u64(a64, 0), vgetq_lane_u64(b64, 1));
   T3 = (uint64x2_t)vmull_p64(vgetq_lane_u64(a64, 1), vgetq_lane_u64(b64, 1));

   T1 = veorq_u64(T1, T2);
   T2 = vreinterpretq_u64_u8(vextq_u8(vdupq_n_u8(0), vreinterpretq_u8_u64(T1), 8));
   T1 = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(T1), vdupq_n_u8(0), 8));
   T0 = veorq_u64(T0, T2);
   T3 = veorq_u64(T3, T1);

   T4 = vshrq_n_u64(T0, 31);
   T0 = vshlq_n_u64(T0, 1);

   T5 = vshrq_n_u64(T3, 31);
   T3 = vshlq_n_u64(T3, 1);

   T2 = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(T4), vdupq_n_u8(0), 12));
   T5 = vreinterpretq_u64_u8(vextq_u8(vdupq_n_u8(0), vreinterpretq_u8_u64(T5), 12));
   T4 = vreinterpretq_u64_u8(vextq_u8(vdupq_n_u8(0), vreinterpretq_u8_u64(T4), 12));
   T0 = vorrq_u64(T0, T4);
   T3 = vorrq_u64(T3, T5);
   T3 = vorrq_u64(T3, T2);

   T4 = vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(T0), 31));
   T5 = vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(T0), 30));
   T2 = vreinterpretq_u64_u32(vshlq_n_u32(vreinterpretq_u32_u64(T0), 25));

   T4 = veorq_u64(T4, T5);
   T4 = veorq_u64(T4, T2);
   T5 = vreinterpretq_u64_u8(vextq_u8(vreinterpretq_u8_u64(T4), vdupq_n_u8(0), 4));
   T3 = veorq_u64(T3, T5);
   T4 = vreinterpretq_u64_u8(vextq_u8(vdupq_n_u8(0), vreinterpretq_u8_u64(T4), 4));
   T0 = veorq_u64(T0, T4);
   T3 = veorq_u64(T3, T0);

   T4 = vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(T0), 1));
   T1 = vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(T0), 2));
   T2 = vreinterpretq_u64_u32(vshrq_n_u32(vreinterpretq_u32_u64(T0), 7));
   T3 = veorq_u64(T3, T1);
   T3 = veorq_u64(T3, T2);
   T3 = veorq_u64(T3, T4);

   vst1_u8(x+0, vrev64_u8(vreinterpret_u8_u64(vget_high_u64(T3))));
   vst1_u8(x+8, vrev64_u8(vreinterpret_u8_u64(vget_low_u64(T3))));
   }

}
