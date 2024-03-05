/*
* (C) 2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/shacal2.h>
#include <arm_neon.h>

namespace Botan {

/*
Only encryption is supported since the inverse round function would
require a different instruction
*/
BOTAN_FUNC_ISA("+crypto+sha2")
void SHACAL2::armv8_encrypt_blocks(const uint8_t in[], uint8_t out[], size_t blocks) const {
   const uint32_t* input32 = reinterpret_cast<const uint32_t*>(in);
   uint32_t* output32 = reinterpret_cast<uint32_t*>(out);

   while(blocks >= 2) {
      uint32x4_t B0_0 = vld1q_u32(input32 + 0);
      uint32x4_t B0_1 = vld1q_u32(input32 + 4);
      uint32x4_t B1_0 = vld1q_u32(input32 + 8);
      uint32x4_t B1_1 = vld1q_u32(input32 + 12);

      B0_0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B0_0)));
      B0_1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B0_1)));
      B1_0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B1_0)));
      B1_1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B1_1)));

      for(size_t i = 0; i != 8; ++i) {
         const auto RK0 = vld1q_u32(&m_RK[8 * i]);
         const auto RK1 = vld1q_u32(&m_RK[8 * i + 4]);

         const auto T0_0 = vsha256hq_u32(B0_0, B0_1, RK0);
         const auto T0_1 = vsha256h2q_u32(B0_1, B0_0, RK0);
         const auto T1_0 = vsha256hq_u32(B1_0, B1_1, RK0);
         const auto T1_1 = vsha256h2q_u32(B1_1, B1_0, RK0);

         B0_0 = vsha256hq_u32(T0_0, T0_1, RK1);
         B0_1 = vsha256h2q_u32(T0_1, T0_0, RK1);
         B1_0 = vsha256hq_u32(T1_0, T1_1, RK1);
         B1_1 = vsha256h2q_u32(T1_1, T1_0, RK1);
      }

      B0_0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B0_0)));
      B0_1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B0_1)));
      B1_0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B1_0)));
      B1_1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B1_1)));

      vst1q_u32(&output32[0], B0_0);
      vst1q_u32(&output32[4], B0_1);
      vst1q_u32(&output32[8], B1_0);
      vst1q_u32(&output32[12], B1_1);

      blocks -= 2;
      input32 += 16;
      output32 += 16;
   }

   while(blocks > 0) {
      uint32x4_t B0 = vld1q_u32(input32 + 0);
      uint32x4_t B1 = vld1q_u32(input32 + 4);

      B0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B0)));
      B1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B1)));

      for(size_t i = 0; i != 8; ++i) {
         const auto RK0 = vld1q_u32(&m_RK[8 * i]);
         const auto RK1 = vld1q_u32(&m_RK[8 * i + 4]);

         const auto T0 = vsha256hq_u32(B0, B1, RK0);
         const auto T1 = vsha256h2q_u32(B1, B0, RK0);

         B0 = vsha256hq_u32(T0, T1, RK1);
         B1 = vsha256h2q_u32(T1, T0, RK1);
      }

      B0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B0)));
      B1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B1)));

      vst1q_u32(&output32[0], B0);
      vst1q_u32(&output32[4], B1);

      blocks--;
      input32 += 8;
      output32 += 8;
   }
}

}  // namespace Botan
