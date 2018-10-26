/*
* NEON ChaCha impl originally written by Jeffrey Walton for Crypto++
* and released as public domain.
*
* Further changes
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <arm_neon.h>

namespace Botan {

namespace {

template <unsigned int R>
inline uint32x4_t RotateLeft(const uint32x4_t& val)
   {
   return vorrq_u32(vshlq_n_u32(val, R), vshrq_n_u32(val, 32 - R));
   }

template <unsigned int R>
inline uint32x4_t RotateRight(const uint32x4_t& val)
   {
   return vorrq_u32(vshlq_n_u32(val, 32 - R), vshrq_n_u32(val, R));
   }

// ChaCha's use of shuffle is really a 4, 8, or 12 byte rotation:
//   * [3,2,1,0] => [0,3,2,1] is Shuffle<1>(x)
//   * [3,2,1,0] => [1,0,3,2] is Shuffle<2>(x)
//   * [3,2,1,0] => [2,1,0,3] is Shuffle<3>(x)
template <unsigned int S>
inline uint32x4_t Shuffle(const uint32x4_t& val)
   {
   return vextq_u32(val, val, S);
   }

#if defined(BOTAN_TARGET_ARCH_IS_ARM64)

template <>
inline uint32x4_t RotateLeft<8>(const uint32x4_t& val)
   {
   const uint8_t maskb[16] = { 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 };
   const uint8x16_t mask = vld1q_u8(maskb);

   return vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(val), mask));
   }

template <>
inline uint32x4_t RotateLeft<16>(const uint32x4_t& val)
   {
   return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(val)));
   }

#endif

}

//static
void ChaCha::chacha_neon_x4(uint8_t output[64*4], uint32_t state[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

   const uint32x4_t state0 = vld1q_u32(state + 0*4);
   const uint32x4_t state1 = vld1q_u32(state + 1*4);
   const uint32x4_t state2 = vld1q_u32(state + 2*4);
   const uint32x4_t state3 = vld1q_u32(state + 3*4);

   const uint64x2_t CTRS[3] = {
      {1, 0}, {2, 0}, {3, 0}
      //{0, 1}, {0, 2}, {0, 3}
   };

   uint32x4_t r0_0 = state0;
   uint32x4_t r0_1 = state1;
   uint32x4_t r0_2 = state2;
   uint32x4_t r0_3 = state3;

   uint32x4_t r1_0 = state0;
   uint32x4_t r1_1 = state1;
   uint32x4_t r1_2 = state2;
   uint32x4_t r1_3 = vreinterpretq_u32_u64(vaddq_u64(vreinterpretq_u64_u32(r0_3), CTRS[0]));

   uint32x4_t r2_0 = state0;
   uint32x4_t r2_1 = state1;
   uint32x4_t r2_2 = state2;
   uint32x4_t r2_3 = vreinterpretq_u32_u64(vaddq_u64(vreinterpretq_u64_u32(r0_3), CTRS[1]));

   uint32x4_t r3_0 = state0;
   uint32x4_t r3_1 = state1;
   uint32x4_t r3_2 = state2;
   uint32x4_t r3_3 = vreinterpretq_u32_u64(vaddq_u64(vreinterpretq_u64_u32(r0_3), CTRS[2]));

   for(size_t i = 0; i != rounds / 2; ++i)
      {
      r0_0 = vaddq_u32(r0_0, r0_1);
      r1_0 = vaddq_u32(r1_0, r1_1);
      r2_0 = vaddq_u32(r2_0, r2_1);
      r3_0 = vaddq_u32(r3_0, r3_1);

      r0_3 = veorq_u32(r0_3, r0_0);
      r1_3 = veorq_u32(r1_3, r1_0);
      r2_3 = veorq_u32(r2_3, r2_0);
      r3_3 = veorq_u32(r3_3, r3_0);

      r0_3 = RotateLeft<16>(r0_3);
      r1_3 = RotateLeft<16>(r1_3);
      r2_3 = RotateLeft<16>(r2_3);
      r3_3 = RotateLeft<16>(r3_3);

      r0_2 = vaddq_u32(r0_2, r0_3);
      r1_2 = vaddq_u32(r1_2, r1_3);
      r2_2 = vaddq_u32(r2_2, r2_3);
      r3_2 = vaddq_u32(r3_2, r3_3);

      r0_1 = veorq_u32(r0_1, r0_2);
      r1_1 = veorq_u32(r1_1, r1_2);
      r2_1 = veorq_u32(r2_1, r2_2);
      r3_1 = veorq_u32(r3_1, r3_2);

      r0_1 = RotateLeft<12>(r0_1);
      r1_1 = RotateLeft<12>(r1_1);
      r2_1 = RotateLeft<12>(r2_1);
      r3_1 = RotateLeft<12>(r3_1);

      r0_0 = vaddq_u32(r0_0, r0_1);
      r1_0 = vaddq_u32(r1_0, r1_1);
      r2_0 = vaddq_u32(r2_0, r2_1);
      r3_0 = vaddq_u32(r3_0, r3_1);

      r0_3 = veorq_u32(r0_3, r0_0);
      r1_3 = veorq_u32(r1_3, r1_0);
      r2_3 = veorq_u32(r2_3, r2_0);
      r3_3 = veorq_u32(r3_3, r3_0);

      r0_3 = RotateLeft<8>(r0_3);
      r1_3 = RotateLeft<8>(r1_3);
      r2_3 = RotateLeft<8>(r2_3);
      r3_3 = RotateLeft<8>(r3_3);

      r0_2 = vaddq_u32(r0_2, r0_3);
      r1_2 = vaddq_u32(r1_2, r1_3);
      r2_2 = vaddq_u32(r2_2, r2_3);
      r3_2 = vaddq_u32(r3_2, r3_3);

      r0_1 = veorq_u32(r0_1, r0_2);
      r1_1 = veorq_u32(r1_1, r1_2);
      r2_1 = veorq_u32(r2_1, r2_2);
      r3_1 = veorq_u32(r3_1, r3_2);

      r0_1 = RotateLeft<7>(r0_1);
      r1_1 = RotateLeft<7>(r1_1);
      r2_1 = RotateLeft<7>(r2_1);
      r3_1 = RotateLeft<7>(r3_1);

      r0_1 = Shuffle<1>(r0_1);
      r0_2 = Shuffle<2>(r0_2);
      r0_3 = Shuffle<3>(r0_3);

      r1_1 = Shuffle<1>(r1_1);
      r1_2 = Shuffle<2>(r1_2);
      r1_3 = Shuffle<3>(r1_3);

      r2_1 = Shuffle<1>(r2_1);
      r2_2 = Shuffle<2>(r2_2);
      r2_3 = Shuffle<3>(r2_3);

      r3_1 = Shuffle<1>(r3_1);
      r3_2 = Shuffle<2>(r3_2);
      r3_3 = Shuffle<3>(r3_3);

      r0_0 = vaddq_u32(r0_0, r0_1);
      r1_0 = vaddq_u32(r1_0, r1_1);
      r2_0 = vaddq_u32(r2_0, r2_1);
      r3_0 = vaddq_u32(r3_0, r3_1);

      r0_3 = veorq_u32(r0_3, r0_0);
      r1_3 = veorq_u32(r1_3, r1_0);
      r2_3 = veorq_u32(r2_3, r2_0);
      r3_3 = veorq_u32(r3_3, r3_0);

      r0_3 = RotateLeft<16>(r0_3);
      r1_3 = RotateLeft<16>(r1_3);
      r2_3 = RotateLeft<16>(r2_3);
      r3_3 = RotateLeft<16>(r3_3);

      r0_2 = vaddq_u32(r0_2, r0_3);
      r1_2 = vaddq_u32(r1_2, r1_3);
      r2_2 = vaddq_u32(r2_2, r2_3);
      r3_2 = vaddq_u32(r3_2, r3_3);

      r0_1 = veorq_u32(r0_1, r0_2);
      r1_1 = veorq_u32(r1_1, r1_2);
      r2_1 = veorq_u32(r2_1, r2_2);
      r3_1 = veorq_u32(r3_1, r3_2);

      r0_1 = RotateLeft<12>(r0_1);
      r1_1 = RotateLeft<12>(r1_1);
      r2_1 = RotateLeft<12>(r2_1);
      r3_1 = RotateLeft<12>(r3_1);

      r0_0 = vaddq_u32(r0_0, r0_1);
      r1_0 = vaddq_u32(r1_0, r1_1);
      r2_0 = vaddq_u32(r2_0, r2_1);
      r3_0 = vaddq_u32(r3_0, r3_1);

      r0_3 = veorq_u32(r0_3, r0_0);
      r1_3 = veorq_u32(r1_3, r1_0);
      r2_3 = veorq_u32(r2_3, r2_0);
      r3_3 = veorq_u32(r3_3, r3_0);

      r0_3 = RotateLeft<8>(r0_3);
      r1_3 = RotateLeft<8>(r1_3);
      r2_3 = RotateLeft<8>(r2_3);
      r3_3 = RotateLeft<8>(r3_3);

      r0_2 = vaddq_u32(r0_2, r0_3);
      r1_2 = vaddq_u32(r1_2, r1_3);
      r2_2 = vaddq_u32(r2_2, r2_3);
      r3_2 = vaddq_u32(r3_2, r3_3);

      r0_1 = veorq_u32(r0_1, r0_2);
      r1_1 = veorq_u32(r1_1, r1_2);
      r2_1 = veorq_u32(r2_1, r2_2);
      r3_1 = veorq_u32(r3_1, r3_2);

      r0_1 = RotateLeft<7>(r0_1);
      r1_1 = RotateLeft<7>(r1_1);
      r2_1 = RotateLeft<7>(r2_1);
      r3_1 = RotateLeft<7>(r3_1);

      r0_1 = Shuffle<3>(r0_1);
      r0_2 = Shuffle<2>(r0_2);
      r0_3 = Shuffle<1>(r0_3);

      r1_1 = Shuffle<3>(r1_1);
      r1_2 = Shuffle<2>(r1_2);
      r1_3 = Shuffle<1>(r1_3);

      r2_1 = Shuffle<3>(r2_1);
      r2_2 = Shuffle<2>(r2_2);
      r2_3 = Shuffle<1>(r2_3);

      r3_1 = Shuffle<3>(r3_1);
      r3_2 = Shuffle<2>(r3_2);
      r3_3 = Shuffle<1>(r3_3);
      }

   r0_0 = vaddq_u32(r0_0, state0);
   r0_1 = vaddq_u32(r0_1, state1);
   r0_2 = vaddq_u32(r0_2, state2);
   r0_3 = vaddq_u32(r0_3, state3);

   r1_0 = vaddq_u32(r1_0, state0);
   r1_1 = vaddq_u32(r1_1, state1);
   r1_2 = vaddq_u32(r1_2, state2);
   r1_3 = vaddq_u32(r1_3, state3);
   r1_3 = vreinterpretq_u32_u64(vaddq_u64(vreinterpretq_u64_u32(r1_3), CTRS[0]));

   r2_0 = vaddq_u32(r2_0, state0);
   r2_1 = vaddq_u32(r2_1, state1);
   r2_2 = vaddq_u32(r2_2, state2);
   r2_3 = vaddq_u32(r2_3, state3);
   r2_3 = vreinterpretq_u32_u64(vaddq_u64(vreinterpretq_u64_u32(r2_3), CTRS[1]));

   r3_0 = vaddq_u32(r3_0, state0);
   r3_1 = vaddq_u32(r3_1, state1);
   r3_2 = vaddq_u32(r3_2, state2);
   r3_3 = vaddq_u32(r3_3, state3);
   r3_3 = vreinterpretq_u32_u64(vaddq_u64(vreinterpretq_u64_u32(r3_3), CTRS[2]));

   vst1q_u8(output + 0*16, vreinterpretq_u8_u32(r0_0));
   vst1q_u8(output + 1*16, vreinterpretq_u8_u32(r0_1));
   vst1q_u8(output + 2*16, vreinterpretq_u8_u32(r0_2));
   vst1q_u8(output + 3*16, vreinterpretq_u8_u32(r0_3));

   vst1q_u8(output + 4*16, vreinterpretq_u8_u32(r1_0));
   vst1q_u8(output + 5*16, vreinterpretq_u8_u32(r1_1));
   vst1q_u8(output + 6*16, vreinterpretq_u8_u32(r1_2));
   vst1q_u8(output + 7*16, vreinterpretq_u8_u32(r1_3));

   vst1q_u8(output +  8*16, vreinterpretq_u8_u32(r2_0));
   vst1q_u8(output +  9*16, vreinterpretq_u8_u32(r2_1));
   vst1q_u8(output + 10*16, vreinterpretq_u8_u32(r2_2));
   vst1q_u8(output + 11*16, vreinterpretq_u8_u32(r2_3));

   vst1q_u8(output + 12*16, vreinterpretq_u8_u32(r3_0));
   vst1q_u8(output + 13*16, vreinterpretq_u8_u32(r3_1));
   vst1q_u8(output + 14*16, vreinterpretq_u8_u32(r3_2));
   vst1q_u8(output + 15*16, vreinterpretq_u8_u32(r3_3));

   state[12] += 4;
   if(state[12] < 4)
      state[13]++;
   }

}
