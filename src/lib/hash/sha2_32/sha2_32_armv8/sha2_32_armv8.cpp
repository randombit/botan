/*
* SHA-256 using CPU instructions in ARMv8
*
* Contributed by Jeffrey Walton. Based on public domain code by
* Johannes Schneiders, Skip Hovsmith and Barry O'Rourke.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sha2_32.h>
#include <arm_neon.h>

namespace Botan {

/*
* SHA-256 using CPU instructions in ARMv8
*/
//static
#if defined(BOTAN_HAS_SHA2_32_ARMV8)
BOTAN_FUNC_ISA("+crypto")
void SHA_256::compress_digest_armv8(secure_vector<uint32_t>& digest, const uint8_t input8[], size_t blocks)
   {
   static const uint32_t K[] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
      0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
      0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
      0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
      0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
      0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
      0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
      0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
      0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
   };

   uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
   uint32x4_t MSG0, MSG1, MSG2, MSG3;
   uint32x4_t TMP0, TMP1, TMP2;

   // Load initial values
   STATE0 = vld1q_u32(&digest[0]);
   STATE1 = vld1q_u32(&digest[4]);

   // Intermediate void* cast due to https://llvm.org/bugs/show_bug.cgi?id=20670
   const uint32_t* input32 = reinterpret_cast<const uint32_t*>(reinterpret_cast<const void*>(input8));

   while (blocks)
      {
      // Save current state
      ABEF_SAVE = STATE0;
      CDGH_SAVE = STATE1;

      MSG0 = vld1q_u32(input32 + 0);
      MSG1 = vld1q_u32(input32 + 4);
      MSG2 = vld1q_u32(input32 + 8);
      MSG3 = vld1q_u32(input32 + 12);

      MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
      MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
      MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
      MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x00]));

      // Rounds 0-3
      MSG0 = vsha256su0q_u32(MSG0, MSG1);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x04]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

      // Rounds 4-7
      MSG1 = vsha256su0q_u32(MSG1, MSG2);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x08]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

      // Rounds 8-11
      MSG2 = vsha256su0q_u32(MSG2, MSG3);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x0c]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

      // Rounds 12-15
      MSG3 = vsha256su0q_u32(MSG3, MSG0);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x10]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

      // Rounds 16-19
      MSG0 = vsha256su0q_u32(MSG0, MSG1);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x14]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

      // Rounds 20-23
      MSG1 = vsha256su0q_u32(MSG1, MSG2);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x18]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

      // Rounds 24-27
      MSG2 = vsha256su0q_u32(MSG2, MSG3);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x1c]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

      // Rounds 28-31
      MSG3 = vsha256su0q_u32(MSG3, MSG0);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x20]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

      // Rounds 32-35
      MSG0 = vsha256su0q_u32(MSG0, MSG1);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x24]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

      // Rounds 36-39
      MSG1 = vsha256su0q_u32(MSG1, MSG2);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x28]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

      // Rounds 40-43
      MSG2 = vsha256su0q_u32(MSG2, MSG3);
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x2c]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
      MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

      // Rounds 44-47
      MSG3 = vsha256su0q_u32(MSG3, MSG0);
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0x30]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
      MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

      // Rounds 48-51
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG1, vld1q_u32(&K[0x34]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

      // Rounds 52-55
      TMP2 = STATE0;
      TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[0x38]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

      // Rounds 56-59
      TMP2 = STATE0;
      TMP1 = vaddq_u32(MSG3, vld1q_u32(&K[0x3c]));
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

      // Rounds 60-63
      TMP2 = STATE0;
      STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
      STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

      // Add back to state
      STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
      STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

      input32 += 64/4;
      blocks--;
      }

   // Save state
   vst1q_u32(&digest[0], STATE0);
   vst1q_u32(&digest[4], STATE1);
   }
#endif

}
