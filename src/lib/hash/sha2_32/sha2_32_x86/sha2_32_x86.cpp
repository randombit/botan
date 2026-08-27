/*
* Based on public domain code by Sean Gulley
*
* Further changes
*
* (C) 2017,2020,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/simd_4x32.h>
#include <botan/internal/stack_scrubbing.h>
#include <immintrin.h>

namespace Botan {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI void sha256_rnds4(SIMD_4x32& S0,
                                                        SIMD_4x32& S1,
                                                        const SIMD_4x32& msg,
                                                        const SIMD_4x32& k) {
   const auto mk = msg + k;
   S1 = SIMD_4x32(_mm_sha256rnds2_epu32(S1.raw(), S0.raw(), mk.raw()));
   S0 = SIMD_4x32(_mm_sha256rnds2_epu32(S0.raw(), S1.raw(), mk.shift_elems_right<2>().raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI void sha256_msg_exp(SIMD_4x32& W0, SIMD_4x32& W1, SIMD_4x32& W2, SIMD_4x32& W3) {
   W2 += SIMD_4x32::alignr4(W1, W0);
   W0 = SIMD_4x32(_mm_sha256msg1_epu32(W0.raw(), W1.raw()));
   W2 = SIMD_4x32(_mm_sha256msg2_epu32(W2.raw(), W1.raw()));

   W3 += SIMD_4x32::alignr4(W2, W1);
   W1 = SIMD_4x32(_mm_sha256msg1_epu32(W1.raw(), W2.raw()));
   W3 = SIMD_4x32(_mm_sha256msg2_epu32(W3.raw(), W2.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHANI void sha256_permute_state(SIMD_4x32& S0, SIMD_4x32& S1) {
   S0 = SIMD_4x32(_mm_shuffle_epi32(S0.raw(), 0b10110001));  // CDAB
   S1 = SIMD_4x32(_mm_shuffle_epi32(S1.raw(), 0b00011011));  // EFGH

   const auto T = SIMD_4x32::alignr8(S0, S1);                  // ABEF
   S1 = SIMD_4x32(_mm_blend_epi16(S1.raw(), S0.raw(), 0xF0));  // CDGH
   S0 = T;
}

// NOLINTEND(portability-simd-intrinsics)

}  // namespace

void BOTAN_FN_ISA_SHANI BOTAN_SCRUB_STACK_AFTER_RETURN SHA_256::compress_digest_x86(digest_type& digest,
                                                                                    std::span<const uint8_t> input_span,
                                                                                    size_t blocks) {
   const uint8_t* input = input_span.data();

   SIMD_4x32 S0 = SIMD_4x32::load_le(&digest[0]);  // NOLINT(*container-data-pointer)
   SIMD_4x32 S1 = SIMD_4x32::load_le(&digest[4]);

   sha256_permute_state(S0, S1);

   while(blocks > 0) {
      const auto S0_SAVE = S0;
      const auto S1_SAVE = S1;

      auto W0 = SIMD_4x32::load_be(input);
      auto W1 = SIMD_4x32::load_be(input + 16);
      auto W2 = SIMD_4x32::load_be(input + 32);
      auto W3 = SIMD_4x32::load_be(input + 48);

      sha256_rnds4(S0, S1, W0, SIMD_4x32::load_le(&SHA256_K[0]));
      sha256_rnds4(S0, S1, W1, SIMD_4x32::load_le(&SHA256_K[4]));
      sha256_rnds4(S0, S1, W2, SIMD_4x32::load_le(&SHA256_K[8]));
      sha256_rnds4(S0, S1, W3, SIMD_4x32::load_le(&SHA256_K[12]));

      W0 = SIMD_4x32(_mm_sha256msg1_epu32(W0.raw(), W1.raw()));
      W1 = SIMD_4x32(_mm_sha256msg1_epu32(W1.raw(), W2.raw()));

      sha256_msg_exp(W2, W3, W0, W1);

      sha256_rnds4(S0, S1, W0, SIMD_4x32::load_le(&SHA256_K[4 * 4]));
      sha256_rnds4(S0, S1, W1, SIMD_4x32::load_le(&SHA256_K[4 * 5]));

      sha256_msg_exp(W0, W1, W2, W3);

      sha256_rnds4(S0, S1, W2, SIMD_4x32::load_le(&SHA256_K[4 * 6]));
      sha256_rnds4(S0, S1, W3, SIMD_4x32::load_le(&SHA256_K[4 * 7]));

      sha256_msg_exp(W2, W3, W0, W1);

      sha256_rnds4(S0, S1, W0, SIMD_4x32::load_le(&SHA256_K[4 * 8]));
      sha256_rnds4(S0, S1, W1, SIMD_4x32::load_le(&SHA256_K[4 * 9]));

      sha256_msg_exp(W0, W1, W2, W3);

      sha256_rnds4(S0, S1, W2, SIMD_4x32::load_le(&SHA256_K[4 * 10]));
      sha256_rnds4(S0, S1, W3, SIMD_4x32::load_le(&SHA256_K[4 * 11]));

      sha256_msg_exp(W2, W3, W0, W1);

      sha256_rnds4(S0, S1, W0, SIMD_4x32::load_le(&SHA256_K[4 * 12]));
      sha256_rnds4(S0, S1, W1, SIMD_4x32::load_le(&SHA256_K[4 * 13]));

      sha256_msg_exp(W0, W1, W2, W3);

      sha256_rnds4(S0, S1, W2, SIMD_4x32::load_le(&SHA256_K[4 * 14]));
      sha256_rnds4(S0, S1, W3, SIMD_4x32::load_le(&SHA256_K[4 * 15]));

      // Add values back to state
      S0 += S0_SAVE;
      S1 += S1_SAVE;

      input += 64;
      blocks--;
   }

   sha256_permute_state(S1, S0);

   S0.store_le(&digest[0]);  // NOLINT(*container-data-pointer)
   S1.store_le(&digest[4]);
}

}  // namespace Botan
