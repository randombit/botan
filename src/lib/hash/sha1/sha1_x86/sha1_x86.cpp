/*
* Based on public domain code by Sean Gulley
*
* Adapted to Botan by Jeffrey Walton.
*
* Further changes
*
* (C) 2017,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/simd_4x32.h>
#include <immintrin.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI SIMD_4x32 sha1_x86_nexte(const SIMD_4x32& x, const SIMD_4x32& y) {
   return SIMD_4x32(_mm_sha1nexte_epu32(x.raw(), y.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI SIMD_4x32 sha1_x86_msg1(const SIMD_4x32& W0, const SIMD_4x32& W1) {
   return SIMD_4x32(_mm_sha1msg1_epu32(W0.raw(), W1.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI void sha1_x86_next_msg(const SIMD_4x32& W0,
                                                             SIMD_4x32& W1,
                                                             SIMD_4x32& W2,
                                                             SIMD_4x32& W3) {
   W3 = SIMD_4x32(_mm_sha1msg1_epu32(W3.raw(), W0.raw()));
   W1 = SIMD_4x32(_mm_sha1msg2_epu32(W1.raw(), W0.raw()));
   W2 ^= W0;
}

template <uint8_t R1, uint8_t R2 = R1>
BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI void sha1_x86_rnds8(SIMD_4x32& ABCD,
                                                          SIMD_4x32& E,
                                                          const SIMD_4x32& W0,
                                                          const SIMD_4x32& W1) {
   auto TE = ABCD;
   ABCD = SIMD_4x32(_mm_sha1rnds4_epu32(ABCD.raw(), sha1_x86_nexte(E, W0).raw(), R1));

   E = ABCD;
   ABCD = SIMD_4x32(_mm_sha1rnds4_epu32(ABCD.raw(), sha1_x86_nexte(TE, W1).raw(), R2));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI SIMD_4x32 rev_words(const SIMD_4x32& v) {
   return SIMD_4x32(_mm_shuffle_epi32(v.raw(), 0b00011011));
}

}  // namespace

void BOTAN_FN_ISA_SHANI SHA_1::sha1_compress_x86(digest_type& digest,
                                                 std::span<const uint8_t> input_span,
                                                 size_t blocks) {
   const uint8_t* input = input_span.data();

   SIMD_4x32 ABCD = rev_words(SIMD_4x32::load_le(&digest[0]));  // NOLINT(*-container-data-pointer)
   SIMD_4x32 E0 = SIMD_4x32(0, 0, 0, digest[4]);

   while(blocks > 0) {
      // Save current hash
      const auto ABCD_SAVE = ABCD;
      const auto E0_SAVE = E0;

      auto W0 = rev_words(SIMD_4x32::load_be(input));
      auto W1 = rev_words(SIMD_4x32::load_be(input + 16));
      auto W2 = rev_words(SIMD_4x32::load_be(input + 32));
      auto W3 = rev_words(SIMD_4x32::load_be(input + 48));

      auto E1 = ABCD;
      ABCD = SIMD_4x32(_mm_sha1rnds4_epu32(ABCD.raw(), _mm_add_epi32(E0.raw(), W0.raw()), 0));

      E0 = ABCD;
      ABCD = SIMD_4x32(_mm_sha1rnds4_epu32(ABCD.raw(), _mm_sha1nexte_epu32(E1.raw(), W1.raw()), 0));

      sha1_x86_rnds8<0>(ABCD, E0, W2, W3);

      W0 = sha1_x86_msg1(W0, W1);
      W1 = sha1_x86_msg1(W1, W2);
      W0 ^= W2;

      sha1_x86_next_msg(W3, W0, W1, W2);
      sha1_x86_next_msg(W0, W1, W2, W3);
      sha1_x86_rnds8<0, 1>(ABCD, E0, W0, W1);

      sha1_x86_next_msg(W1, W2, W3, W0);
      sha1_x86_next_msg(W2, W3, W0, W1);
      sha1_x86_rnds8<1>(ABCD, E0, W2, W3);

      sha1_x86_next_msg(W3, W0, W1, W2);
      sha1_x86_next_msg(W0, W1, W2, W3);
      sha1_x86_rnds8<1>(ABCD, E0, W0, W1);

      sha1_x86_next_msg(W1, W2, W3, W0);
      sha1_x86_next_msg(W2, W3, W0, W1);
      sha1_x86_rnds8<2>(ABCD, E0, W2, W3);

      sha1_x86_next_msg(W3, W0, W1, W2);
      sha1_x86_next_msg(W0, W1, W2, W3);
      sha1_x86_rnds8<2>(ABCD, E0, W0, W1);

      sha1_x86_next_msg(W1, W2, W3, W0);
      sha1_x86_next_msg(W2, W3, W0, W1);
      sha1_x86_rnds8<2, 3>(ABCD, E0, W2, W3);

      sha1_x86_next_msg(W3, W0, W1, W2);
      sha1_x86_next_msg(W0, W1, W2, W3);
      sha1_x86_rnds8<3>(ABCD, E0, W0, W1);

      sha1_x86_next_msg(W1, W2, W3, W0);
      sha1_x86_next_msg(W2, W3, W0, W1);
      sha1_x86_rnds8<3>(ABCD, E0, W2, W3);

      ABCD += ABCD_SAVE;
      E0 = sha1_x86_nexte(E0, E0_SAVE);

      input += 64;
      blocks--;
   }

   rev_words(ABCD).store_le(&digest[0]);  // NOLINT(*-container-data-pointer)
   digest[4] = _mm_extract_epi32(E0.raw(), 3);
}

}  // namespace Botan
