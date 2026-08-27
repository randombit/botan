/*
* SHA-512 using CPU instructions in ARMv8
*
* (C) 2023 René Fischer
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <arm_neon.h>

namespace Botan {

/*
* SHA-512 using CPU instructions in ARMv8
*/
void BOTAN_FN_ISA_SHA512 SHA_512::compress_digest_armv8(digest_type& digest,
                                                        std::span<const uint8_t> input8,
                                                        size_t blocks) {
   // Load initial values
   uint64x2_t STATE0 = vld1q_u64(&digest[0]);  // ab NOLINT(*-container-data-pointer)
   uint64x2_t STATE1 = vld1q_u64(&digest[2]);  // cd
   uint64x2_t STATE2 = vld1q_u64(&digest[4]);  // ef
   uint64x2_t STATE3 = vld1q_u64(&digest[6]);  // gh

   const uint8_t* input = input8.data();

   while(blocks > 0) {
      // Save current state
      const uint64x2_t AB_SAVE = STATE0;
      const uint64x2_t CD_SAVE = STATE1;
      const uint64x2_t EF_SAVE = STATE2;
      const uint64x2_t GH_SAVE = STATE3;

      uint64x2_t MSG0 = vreinterpretq_u64_u8(vld1q_u8(input + 0));
      uint64x2_t MSG1 = vreinterpretq_u64_u8(vld1q_u8(input + 16));
      uint64x2_t MSG2 = vreinterpretq_u64_u8(vld1q_u8(input + 32));
      uint64x2_t MSG3 = vreinterpretq_u64_u8(vld1q_u8(input + 48));
      uint64x2_t MSG4 = vreinterpretq_u64_u8(vld1q_u8(input + 64));
      uint64x2_t MSG5 = vreinterpretq_u64_u8(vld1q_u8(input + 80));
      uint64x2_t MSG6 = vreinterpretq_u64_u8(vld1q_u8(input + 96));
      uint64x2_t MSG7 = vreinterpretq_u64_u8(vld1q_u8(input + 112));

      MSG0 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG0)));
      MSG1 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG1)));
      MSG2 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG2)));
      MSG3 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG3)));
      MSG4 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG4)));
      MSG5 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG5)));
      MSG6 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG6)));
      MSG7 = vreinterpretq_u64_u8(vrev64q_u8(vreinterpretq_u8_u64(MSG7)));

      uint64x2_t MSG_K;
      uint64x2_t TSTATE0;
      uint64x2_t TSTATE1;

      // Rounds 0-1
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&SHA512_K[2 * 0]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 2-3
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&SHA512_K[2 * 1]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 4-5
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&SHA512_K[2 * 2]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 6-7
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&SHA512_K[2 * 3]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 8-9
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&SHA512_K[2 * 4]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 10-11
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&SHA512_K[2 * 5]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 12-13
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&SHA512_K[2 * 6]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 14-15
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&SHA512_K[2 * 7]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 16-17
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&SHA512_K[2 * 8]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 18-19
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&SHA512_K[2 * 9]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 20-21
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&SHA512_K[2 * 10]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 22-23
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&SHA512_K[2 * 11]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 24-25
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&SHA512_K[2 * 12]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 26-27
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&SHA512_K[2 * 13]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 28-29
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&SHA512_K[2 * 14]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 30-31
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&SHA512_K[2 * 15]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 32-33
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&SHA512_K[2 * 16]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 34-35
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&SHA512_K[2 * 17]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 36-37
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&SHA512_K[2 * 18]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 38-39
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&SHA512_K[2 * 19]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 40-41
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&SHA512_K[2 * 20]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 42-43
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&SHA512_K[2 * 21]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 44-45
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&SHA512_K[2 * 22]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 46-47
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&SHA512_K[2 * 23]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 48-49
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&SHA512_K[2 * 24]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG0 = vsha512su1q_u64(vsha512su0q_u64(MSG0, MSG1), MSG7, vextq_u64(MSG4, MSG5, 1));

      // Rounds 50-51
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&SHA512_K[2 * 25]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG1 = vsha512su1q_u64(vsha512su0q_u64(MSG1, MSG2), MSG0, vextq_u64(MSG5, MSG6, 1));

      // Rounds 52-53
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&SHA512_K[2 * 26]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG2 = vsha512su1q_u64(vsha512su0q_u64(MSG2, MSG3), MSG1, vextq_u64(MSG6, MSG7, 1));

      // Rounds 54-55
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&SHA512_K[2 * 27]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG3 = vsha512su1q_u64(vsha512su0q_u64(MSG3, MSG4), MSG2, vextq_u64(MSG7, MSG0, 1));

      // Rounds 56-57
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&SHA512_K[2 * 28]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);
      MSG4 = vsha512su1q_u64(vsha512su0q_u64(MSG4, MSG5), MSG3, vextq_u64(MSG0, MSG1, 1));

      // Rounds 58-59
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&SHA512_K[2 * 29]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);
      MSG5 = vsha512su1q_u64(vsha512su0q_u64(MSG5, MSG6), MSG4, vextq_u64(MSG1, MSG2, 1));

      // Rounds 60-61
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&SHA512_K[2 * 30]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);
      MSG6 = vsha512su1q_u64(vsha512su0q_u64(MSG6, MSG7), MSG5, vextq_u64(MSG2, MSG3, 1));

      // Rounds 62-63
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&SHA512_K[2 * 31]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);
      MSG7 = vsha512su1q_u64(vsha512su0q_u64(MSG7, MSG0), MSG6, vextq_u64(MSG3, MSG4, 1));

      // Rounds 64-65
      MSG_K = vaddq_u64(MSG0, vld1q_u64(&SHA512_K[2 * 32]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);

      // Rounds 66-67
      MSG_K = vaddq_u64(MSG1, vld1q_u64(&SHA512_K[2 * 33]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);

      // Rounds 68-69
      MSG_K = vaddq_u64(MSG2, vld1q_u64(&SHA512_K[2 * 34]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);

      // Rounds 70-71
      MSG_K = vaddq_u64(MSG3, vld1q_u64(&SHA512_K[2 * 35]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);

      // Rounds 72-73
      MSG_K = vaddq_u64(MSG4, vld1q_u64(&SHA512_K[2 * 36]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE3);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE2, STATE3, 1), vextq_u64(STATE1, STATE2, 1));
      STATE3 = vsha512h2q_u64(TSTATE1, STATE1, STATE0);
      STATE1 = vaddq_u64(STATE1, TSTATE1);

      // Rounds 74-75
      MSG_K = vaddq_u64(MSG5, vld1q_u64(&SHA512_K[2 * 37]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE2);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE1, STATE2, 1), vextq_u64(STATE0, STATE1, 1));
      STATE2 = vsha512h2q_u64(TSTATE1, STATE0, STATE3);
      STATE0 = vaddq_u64(STATE0, TSTATE1);

      // Rounds 76-77
      MSG_K = vaddq_u64(MSG6, vld1q_u64(&SHA512_K[2 * 38]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE1);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE0, STATE1, 1), vextq_u64(STATE3, STATE0, 1));
      STATE1 = vsha512h2q_u64(TSTATE1, STATE3, STATE2);
      STATE3 = vaddq_u64(STATE3, TSTATE1);

      // Rounds 78-79
      MSG_K = vaddq_u64(MSG7, vld1q_u64(&SHA512_K[2 * 39]));
      TSTATE0 = vaddq_u64(vextq_u64(MSG_K, MSG_K, 1), STATE0);
      TSTATE1 = vsha512hq_u64(TSTATE0, vextq_u64(STATE3, STATE0, 1), vextq_u64(STATE2, STATE3, 1));
      STATE0 = vsha512h2q_u64(TSTATE1, STATE2, STATE1);
      STATE2 = vaddq_u64(STATE2, TSTATE1);

      // Add back to state
      STATE0 = vaddq_u64(STATE0, AB_SAVE);
      STATE1 = vaddq_u64(STATE1, CD_SAVE);
      STATE2 = vaddq_u64(STATE2, EF_SAVE);
      STATE3 = vaddq_u64(STATE3, GH_SAVE);

      input += 128;
      blocks--;
   }

   // Save state
   vst1q_u64(&digest[0], STATE0);  // NOLINT(*-container-data-pointer)
   vst1q_u64(&digest[2], STATE1);
   vst1q_u64(&digest[4], STATE2);
   vst1q_u64(&digest[6], STATE3);
}

}  // namespace Botan
