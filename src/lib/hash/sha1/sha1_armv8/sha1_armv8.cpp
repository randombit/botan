/*
* SHA-1 using CPU instructions in ARMv8
*
* Contributed by Jeffrey Walton. Based on public domain code by
* Johannes Schneiders, Skip Hovsmith and Barry O'Rourke.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sha160.h>
#include <arm_neon.h>

namespace Botan {

/*
* SHA-1 using CPU instructions in ARMv8
*/
//static
#if defined(BOTAN_HAS_SHA1_ARMV8)
BOTAN_FUNC_ISA("+crypto")
void SHA_160::sha1_armv8_compress_n(secure_vector<uint32_t>& digest, const uint8_t input8[], size_t blocks)
   {
   uint32x4_t ABCD;
   uint32_t E0;

   // Load magic constants
   const uint32x4_t C0 = vdupq_n_u32(0x5A827999);
   const uint32x4_t C1 = vdupq_n_u32(0x6ED9EBA1);
   const uint32x4_t C2 = vdupq_n_u32(0x8F1BBCDC);
   const uint32x4_t C3 = vdupq_n_u32(0xCA62C1D6);

   ABCD = vld1q_u32(&digest[0]);
   E0 = digest[4];

   // Intermediate void* cast due to https://llvm.org/bugs/show_bug.cgi?id=20670
   const uint32_t* input32 = reinterpret_cast<const uint32_t*>(reinterpret_cast<const void*>(input8));

   while (blocks)
      {
      // Save current hash
      const uint32x4_t ABCD_SAVED = ABCD;
      const uint32_t E0_SAVED = E0;

      uint32x4_t MSG0, MSG1, MSG2, MSG3;
      uint32x4_t TMP0, TMP1;
      uint32_t E1;

      MSG0 = vld1q_u32(input32 + 0);
      MSG1 = vld1q_u32(input32 + 4);
      MSG2 = vld1q_u32(input32 + 8);
      MSG3 = vld1q_u32(input32 + 12);

      MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
      MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
      MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
      MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

      TMP0 = vaddq_u32(MSG0, C0);
      TMP1 = vaddq_u32(MSG1, C0);

      // Rounds 0-3
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1cq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG2, C0);
      MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

      // Rounds 4-7
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1cq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG3, C0);
      MSG0 = vsha1su1q_u32(MSG0, MSG3);
      MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

      // Rounds 8-11
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1cq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG0, C0);
      MSG1 = vsha1su1q_u32(MSG1, MSG0);
      MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

      // Rounds 12-15
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1cq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG1, C1);
      MSG2 = vsha1su1q_u32(MSG2, MSG1);
      MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

      // Rounds 16-19
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1cq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG2, C1);
      MSG3 = vsha1su1q_u32(MSG3, MSG2);
      MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

      // Rounds 20-23
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG3, C1);
      MSG0 = vsha1su1q_u32(MSG0, MSG3);
      MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

      // Rounds 24-27
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG0, C1);
      MSG1 = vsha1su1q_u32(MSG1, MSG0);
      MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

      // Rounds 28-31
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG1, C1);
      MSG2 = vsha1su1q_u32(MSG2, MSG1);
      MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

      // Rounds 32-35
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG2, C2);
      MSG3 = vsha1su1q_u32(MSG3, MSG2);
      MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

      // Rounds 36-39
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG3, C2);
      MSG0 = vsha1su1q_u32(MSG0, MSG3);
      MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

      // Rounds 40-43
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1mq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG0, C2);
      MSG1 = vsha1su1q_u32(MSG1, MSG0);
      MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

      // Rounds 44-47
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1mq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG1, C2);
      MSG2 = vsha1su1q_u32(MSG2, MSG1);
      MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

      // Rounds 48-51
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1mq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG2, C2);
      MSG3 = vsha1su1q_u32(MSG3, MSG2);
      MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

      // Rounds 52-55
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1mq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG3, C3);
      MSG0 = vsha1su1q_u32(MSG0, MSG3);
      MSG1 = vsha1su0q_u32(MSG1, MSG2, MSG3);

      // Rounds 56-59
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1mq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG0, C3);
      MSG1 = vsha1su1q_u32(MSG1, MSG0);
      MSG2 = vsha1su0q_u32(MSG2, MSG3, MSG0);

      // Rounds 60-63
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG1, C3);
      MSG2 = vsha1su1q_u32(MSG2, MSG1);
      MSG3 = vsha1su0q_u32(MSG3, MSG0, MSG1);

      // Rounds 64-67
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E0, TMP0);
      TMP0 = vaddq_u32(MSG2, C3);
      MSG3 = vsha1su1q_u32(MSG3, MSG2);
      MSG0 = vsha1su0q_u32(MSG0, MSG1, MSG2);

      // Rounds 68-71
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E1, TMP1);
      TMP1 = vaddq_u32(MSG3, C3);
      MSG0 = vsha1su1q_u32(MSG0, MSG3);

      // Rounds 72-75
      E1 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E0, TMP0);

      // Rounds 76-79
      E0 = vsha1h_u32(vgetq_lane_u32(ABCD, 0));
      ABCD = vsha1pq_u32(ABCD, E1, TMP1);

      // Add state back
      E0 += E0_SAVED;
      ABCD = vaddq_u32(ABCD_SAVED, ABCD);

      input32 += 64/4;
      blocks--;
      }

   // Save digest
   vst1q_u32(&digest[0], ABCD);
   digest[4] = E0;
   }
#endif

}
