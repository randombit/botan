/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm4.h>
#include <arm_neon.h>

namespace Botan {

namespace {

alignas(16) static const uint8_t qswap_tbl[16] = {12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3};

alignas(16) static const uint8_t bswap_tbl[16] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

inline uint32x4_t qswap_32(uint32x4_t B) {
   return vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(B), vld1q_u8(qswap_tbl)));
}

inline uint32x4_t bswap_32(uint32x4_t B) {
   return vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(B)));
}

/*
 Swap both the quad-words and bytes within each word
 equivalent to return bswap_32(qswap_32(B))
*/
inline uint32x4_t bqswap_32(uint32x4_t B) {
   return vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(B), vld1q_u8(bswap_tbl)));
}

inline void BOTAN_FUNC_ISA("arch=armv8.2-a+sm4")
   SM4_E(uint32x4_t& B0, uint32x4_t& B1, uint32x4_t& B2, uint32x4_t& B3, uint32x4_t K) {
   B0 = vsm4eq_u32(B0, K);
   B1 = vsm4eq_u32(B1, K);
   B2 = vsm4eq_u32(B2, K);
   B3 = vsm4eq_u32(B3, K);
}

}  // namespace

void BOTAN_FUNC_ISA("arch=armv8.2-a+sm4") SM4::sm4_armv8_encrypt(const uint8_t input8[],
                                                                 uint8_t output8[],
                                                                 size_t blocks) const {
   const uint32x4_t K0 = vld1q_u32(&m_RK[0]);
   const uint32x4_t K1 = vld1q_u32(&m_RK[4]);
   const uint32x4_t K2 = vld1q_u32(&m_RK[8]);
   const uint32x4_t K3 = vld1q_u32(&m_RK[12]);
   const uint32x4_t K4 = vld1q_u32(&m_RK[16]);
   const uint32x4_t K5 = vld1q_u32(&m_RK[20]);
   const uint32x4_t K6 = vld1q_u32(&m_RK[24]);
   const uint32x4_t K7 = vld1q_u32(&m_RK[28]);

   const uint32_t* input32 = reinterpret_cast<const uint32_t*>(reinterpret_cast<const void*>(input8));
   uint32_t* output32 = reinterpret_cast<uint32_t*>(reinterpret_cast<void*>(output8));

   while(blocks >= 4) {
      uint32x4_t B0 = bswap_32(vld1q_u32(input32));
      uint32x4_t B1 = bswap_32(vld1q_u32(input32 + 4));
      uint32x4_t B2 = bswap_32(vld1q_u32(input32 + 8));
      uint32x4_t B3 = bswap_32(vld1q_u32(input32 + 12));

      SM4_E(B0, B1, B2, B3, K0);
      SM4_E(B0, B1, B2, B3, K1);
      SM4_E(B0, B1, B2, B3, K2);
      SM4_E(B0, B1, B2, B3, K3);
      SM4_E(B0, B1, B2, B3, K4);
      SM4_E(B0, B1, B2, B3, K5);
      SM4_E(B0, B1, B2, B3, K6);
      SM4_E(B0, B1, B2, B3, K7);

      vst1q_u32(output32, bqswap_32(B0));
      vst1q_u32(output32 + 4, bqswap_32(B1));
      vst1q_u32(output32 + 8, bqswap_32(B2));
      vst1q_u32(output32 + 12, bqswap_32(B3));

      input32 += 4 * 4;
      output32 += 4 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint32x4_t B = bswap_32(vld1q_u32(input32));

      B = vsm4eq_u32(B, K0);
      B = vsm4eq_u32(B, K1);
      B = vsm4eq_u32(B, K2);
      B = vsm4eq_u32(B, K3);
      B = vsm4eq_u32(B, K4);
      B = vsm4eq_u32(B, K5);
      B = vsm4eq_u32(B, K6);
      B = vsm4eq_u32(B, K7);

      vst1q_u32(output32, bqswap_32(B));

      input32 += 4;
      output32 += 4;
   }
}

void BOTAN_FUNC_ISA("arch=armv8.2-a+sm4") SM4::sm4_armv8_decrypt(const uint8_t input8[],
                                                                 uint8_t output8[],
                                                                 size_t blocks) const {
   const uint32x4_t K0 = qswap_32(vld1q_u32(&m_RK[0]));
   const uint32x4_t K1 = qswap_32(vld1q_u32(&m_RK[4]));
   const uint32x4_t K2 = qswap_32(vld1q_u32(&m_RK[8]));
   const uint32x4_t K3 = qswap_32(vld1q_u32(&m_RK[12]));
   const uint32x4_t K4 = qswap_32(vld1q_u32(&m_RK[16]));
   const uint32x4_t K5 = qswap_32(vld1q_u32(&m_RK[20]));
   const uint32x4_t K6 = qswap_32(vld1q_u32(&m_RK[24]));
   const uint32x4_t K7 = qswap_32(vld1q_u32(&m_RK[28]));

   const uint32_t* input32 = reinterpret_cast<const uint32_t*>(reinterpret_cast<const void*>(input8));
   uint32_t* output32 = reinterpret_cast<uint32_t*>(reinterpret_cast<void*>(output8));

   while(blocks >= 4) {
      uint32x4_t B0 = bswap_32(vld1q_u32(input32));
      uint32x4_t B1 = bswap_32(vld1q_u32(input32 + 4));
      uint32x4_t B2 = bswap_32(vld1q_u32(input32 + 8));
      uint32x4_t B3 = bswap_32(vld1q_u32(input32 + 12));

      SM4_E(B0, B1, B2, B3, K7);
      SM4_E(B0, B1, B2, B3, K6);
      SM4_E(B0, B1, B2, B3, K5);
      SM4_E(B0, B1, B2, B3, K4);
      SM4_E(B0, B1, B2, B3, K3);
      SM4_E(B0, B1, B2, B3, K2);
      SM4_E(B0, B1, B2, B3, K1);
      SM4_E(B0, B1, B2, B3, K0);

      vst1q_u32(output32, bqswap_32(B0));
      vst1q_u32(output32 + 4, bqswap_32(B1));
      vst1q_u32(output32 + 8, bqswap_32(B2));
      vst1q_u32(output32 + 12, bqswap_32(B3));

      input32 += 4 * 4;
      output32 += 4 * 4;
      blocks -= 4;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint32x4_t B = bswap_32(vld1q_u32(input32));

      B = vsm4eq_u32(B, K7);
      B = vsm4eq_u32(B, K6);
      B = vsm4eq_u32(B, K5);
      B = vsm4eq_u32(B, K4);
      B = vsm4eq_u32(B, K3);
      B = vsm4eq_u32(B, K2);
      B = vsm4eq_u32(B, K1);
      B = vsm4eq_u32(B, K0);

      vst1q_u32(output32, bqswap_32(B));

      input32 += 4;
      output32 += 4;
   }
}

}  // namespace Botan
