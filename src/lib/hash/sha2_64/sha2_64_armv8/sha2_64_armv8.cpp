/*
* SHA-512 using CPU instructions in ARMv8
*
* (C) 2023 René Fischer
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>
#include <arm_neon.h>

namespace Botan {

/*
* SHA-512 using CPU instructions in ARMv8
*/
BOTAN_FUNC_ISA("arch=armv8.2-a+sha3")
void SHA_512::compress_digest_armv8(digest_type& digest, std::span<const uint8_t> input8, size_t blocks) {
   alignas(128) static const uint64_t K[] = {
      0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538,
      0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242, 0x12835B0145706FBE,
      0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
      0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
      0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5, 0x983E5152EE66DFAB,
      0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
      0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED,
      0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
      0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
      0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8, 0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
      0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373,
      0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
      0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B, 0xCA273ECEEA26619C,
      0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
      0x113F9804BEF90DAE, 0x1B710B35131C471B, 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
      0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817};

   // Load initial values
   uint64x2_t STATE0 = vld1q_u64(&digest[0]);  // ab
   uint64x2_t STATE1 = vld1q_u64(&digest[2]);  // cd
   uint64x2_t STATE2 = vld1q_u64(&digest[4]);  // ef
   uint64x2_t STATE3 = vld1q_u64(&digest[6]);  // gh

   const uint64_t* input64 = reinterpret_cast<const uint64_t*>(input8.data());

   while(blocks > 0) {
      // Save current state
      const uint64x2_t AB_SAVE = STATE0;
      const uint64x2_t CD_SAVE = STATE1;
      const uint64x2_t EF_SAVE = STATE2;
      const uint64x2_t GH_SAVE = STATE3;

      uint64x2_t MSG0 = vld1q_u64(input64 + 0);
      uint64x2_t MSG1 = vld1q_u64(input64 + 2);
      uint64x2_t MSG2 = vld1q_u64(input64 + 4);
      uint64x2_t MSG3 = vld1q_u64(input64 + 6);
      uint64x2_t MSG4 = vld1q_u64(input64 + 8);
      uint64x2_t MSG5 = vld1q_u64(input64 + 10);
      uint64x2_t MSG6 = vld1q_u64(input64 + 12);
      uint64x2_t MSG7 = vld1q_u64(input64 + 14);

      MSG0 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG0)));
      MSG1 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG1)));
      MSG2 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG2)));
      MSG3 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG3)));
      MSG4 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG4)));
      MSG5 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG5)));
      MSG6 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG6)));
      MSG7 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG7)));

      uint64x2_t MSG_K, TSTATE0, TSTATE1;

      // Rounds 0-1
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&K[2 * 0]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 2-3
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&K[2 * 1]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 4-5
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&K[2 * 2]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 6-7
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&K[2 * 3]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 8-9
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&K[2 * 4]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 10-11
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&K[2 * 5]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 12-13
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&K[2 * 6]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 14-15
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&K[2 * 7]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 16-17
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&K[2 * 8]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 18-19
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&K[2 * 9]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 20-21
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&K[2 * 10]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 22-23
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&K[2 * 11]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 24-25
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&K[2 * 12]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 26-27
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&K[2 * 13]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 28-29
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&K[2 * 14]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 30-31
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&K[2 * 15]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 32-33
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&K[2 * 16]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 34-35
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&K[2 * 17]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 36-37
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&K[2 * 18]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 38-39
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&K[2 * 19]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 40-41
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&K[2 * 20]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 42-43
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&K[2 * 21]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 44-45
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&K[2 * 22]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 46-47
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&K[2 * 23]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 48-49
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&K[2 * 24]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 50-51
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&K[2 * 25]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 52-53
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&K[2 * 26]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 54-55
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&K[2 * 27]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 56-57
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&K[2 * 28]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 58-59
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&K[2 * 29]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 60-61
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&K[2 * 30]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 62-63
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&K[2 * 31]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 64-65
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&K[2 * 32]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);

      // Rounds 66-67
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&K[2 * 33]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);

      // Rounds 68-69
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&K[2 * 34]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);

      // Rounds 70-71
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&K[2 * 35]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);

      // Rounds 72-73
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&K[2 * 36]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);

      // Rounds 74-75
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&K[2 * 37]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);

      // Rounds 76-77
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&K[2 * 38]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);

      // Rounds 78-79
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&K[2 * 39]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);

      // Add back to state
      STATE0 = vaddq_u64(STATE0, AB_SAVE);
      STATE1 = vaddq_u64(STATE1, CD_SAVE);
      STATE2 = vaddq_u64(STATE2, EF_SAVE);
      STATE3 = vaddq_u64(STATE3, GH_SAVE);

      input64 += 64 / 4;
      blocks--;
   }

   // Save state
   vst1q_u64(&digest[0], STATE0);
   vst1q_u64(&digest[2], STATE1);
   vst1q_u64(&digest[4], STATE2);
   vst1q_u64(&digest[6], STATE3);
}

}  // namespace Botan
