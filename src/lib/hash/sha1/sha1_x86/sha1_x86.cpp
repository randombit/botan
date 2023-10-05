/*
* SHA-1 using Intel SHA intrinsic
*
* Based on public domain code by Sean Gulley
* (https://github.com/mitls/hacl-star/tree/master/experimental/hash)
* Adapted to Botan by Jeffrey Walton.
*
* Further changes
*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>
#include <immintrin.h>

namespace Botan {

BOTAN_FUNC_ISA("sha,ssse3,sse4.1")
void SHA_1::sha1_compress_x86(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   const __m128i MASK = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);
   const __m128i* input_mm = reinterpret_cast<const __m128i*>(input.data());

   uint32_t* state = digest.data();

   // Load initial values
   __m128i ABCD = _mm_loadu_si128(reinterpret_cast<__m128i*>(state));
   __m128i E0 = _mm_set_epi32(state[4], 0, 0, 0);
   ABCD = _mm_shuffle_epi32(ABCD, 0x1B);

   while(blocks) {
      // Save current hash
      const __m128i ABCD_SAVE = ABCD;
      const __m128i E0_SAVE = E0;

      __m128i MSG0, MSG1, MSG2, MSG3;
      __m128i E1;

      // Rounds 0-3
      MSG0 = _mm_loadu_si128(input_mm + 0);
      MSG0 = _mm_shuffle_epi8(MSG0, MASK);
      E0 = _mm_add_epi32(E0, MSG0);
      E1 = ABCD;
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

      // Rounds 4-7
      MSG1 = _mm_loadu_si128(input_mm + 1);
      MSG1 = _mm_shuffle_epi8(MSG1, MASK);
      E1 = _mm_sha1nexte_epu32(E1, MSG1);
      E0 = ABCD;
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
      MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

      // Rounds 8-11
      MSG2 = _mm_loadu_si128(input_mm + 2);
      MSG2 = _mm_shuffle_epi8(MSG2, MASK);
      E0 = _mm_sha1nexte_epu32(E0, MSG2);
      E1 = ABCD;
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
      MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
      MSG0 = _mm_xor_si128(MSG0, MSG2);

      // Rounds 12-15
      MSG3 = _mm_loadu_si128(input_mm + 3);
      MSG3 = _mm_shuffle_epi8(MSG3, MASK);
      E1 = _mm_sha1nexte_epu32(E1, MSG3);
      E0 = ABCD;
      MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
      MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
      MSG1 = _mm_xor_si128(MSG1, MSG3);

      // Rounds 16-19
      E0 = _mm_sha1nexte_epu32(E0, MSG0);
      E1 = ABCD;
      MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
      MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
      MSG2 = _mm_xor_si128(MSG2, MSG0);

      // Rounds 20-23
      E1 = _mm_sha1nexte_epu32(E1, MSG1);
      E0 = ABCD;
      MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
      MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
      MSG3 = _mm_xor_si128(MSG3, MSG1);

      // Rounds 24-27
      E0 = _mm_sha1nexte_epu32(E0, MSG2);
      E1 = ABCD;
      MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
      MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
      MSG0 = _mm_xor_si128(MSG0, MSG2);

      // Rounds 28-31
      E1 = _mm_sha1nexte_epu32(E1, MSG3);
      E0 = ABCD;
      MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
      MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
      MSG1 = _mm_xor_si128(MSG1, MSG3);

      // Rounds 32-35
      E0 = _mm_sha1nexte_epu32(E0, MSG0);
      E1 = ABCD;
      MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
      MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
      MSG2 = _mm_xor_si128(MSG2, MSG0);

      // Rounds 36-39
      E1 = _mm_sha1nexte_epu32(E1, MSG1);
      E0 = ABCD;
      MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
      MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
      MSG3 = _mm_xor_si128(MSG3, MSG1);

      // Rounds 40-43
      E0 = _mm_sha1nexte_epu32(E0, MSG2);
      E1 = ABCD;
      MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
      MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
      MSG0 = _mm_xor_si128(MSG0, MSG2);

      // Rounds 44-47
      E1 = _mm_sha1nexte_epu32(E1, MSG3);
      E0 = ABCD;
      MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
      MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
      MSG1 = _mm_xor_si128(MSG1, MSG3);

      // Rounds 48-51
      E0 = _mm_sha1nexte_epu32(E0, MSG0);
      E1 = ABCD;
      MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
      MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
      MSG2 = _mm_xor_si128(MSG2, MSG0);

      // Rounds 52-55
      E1 = _mm_sha1nexte_epu32(E1, MSG1);
      E0 = ABCD;
      MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
      MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
      MSG3 = _mm_xor_si128(MSG3, MSG1);

      // Rounds 56-59
      E0 = _mm_sha1nexte_epu32(E0, MSG2);
      E1 = ABCD;
      MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
      MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
      MSG0 = _mm_xor_si128(MSG0, MSG2);

      // Rounds 60-63
      E1 = _mm_sha1nexte_epu32(E1, MSG3);
      E0 = ABCD;
      MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
      MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
      MSG1 = _mm_xor_si128(MSG1, MSG3);

      // Rounds 64-67
      E0 = _mm_sha1nexte_epu32(E0, MSG0);
      E1 = ABCD;
      MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
      MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
      MSG2 = _mm_xor_si128(MSG2, MSG0);

      // Rounds 68-71
      E1 = _mm_sha1nexte_epu32(E1, MSG1);
      E0 = ABCD;
      MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
      MSG3 = _mm_xor_si128(MSG3, MSG1);

      // Rounds 72-75
      E0 = _mm_sha1nexte_epu32(E0, MSG2);
      E1 = ABCD;
      MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
      ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

      // Rounds 76-79
      E1 = _mm_sha1nexte_epu32(E1, MSG3);
      E0 = ABCD;
      ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

      // Add values back to state
      E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
      ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

      input_mm += 4;
      blocks--;
   }

   // Save state
   ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
   _mm_storeu_si128(reinterpret_cast<__m128i*>(state), ABCD);
   state[4] = _mm_extract_epi32(E0, 3);
}

}  // namespace Botan
