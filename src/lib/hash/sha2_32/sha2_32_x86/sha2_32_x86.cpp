/*
* Based on public domain code by Sean Gulley
*
* Further changes
*
* (C) 2017,2020,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/simd_32.h>
#include <immintrin.h>

namespace Botan {

namespace {

BOTAN_FUNC_ISA_INLINE("sha,sse2")
void sha256_rnds4(SIMD_4x32& S0, SIMD_4x32& S1, const SIMD_4x32& msg, const SIMD_4x32& k) {
   const auto mk = msg + k;
   S1 = SIMD_4x32(_mm_sha256rnds2_epu32(S1.raw(), S0.raw(), mk.raw()));
   S0 = SIMD_4x32(_mm_sha256rnds2_epu32(S0.raw(), S1.raw(), mk.shift_elems_right<2>().raw()));
}

BOTAN_FUNC_ISA_INLINE("sha,ssse3") void sha256_msg_exp(SIMD_4x32& m0, SIMD_4x32& m1, SIMD_4x32& m2) {
   m2 += SIMD_4x32(_mm_alignr_epi8(m1.raw(), m0.raw(), 4));
   m0 = SIMD_4x32(_mm_sha256msg1_epu32(m0.raw(), m1.raw()));
   m2 = SIMD_4x32(_mm_sha256msg2_epu32(m2.raw(), m1.raw()));
}

BOTAN_FUNC_ISA_INLINE("ssse3,sse4.1") void sha256_permute_state(SIMD_4x32& S0, SIMD_4x32& S1) {
   S0 = SIMD_4x32(_mm_shuffle_epi32(S0.raw(), 0b10110001));  // CDAB
   S1 = SIMD_4x32(_mm_shuffle_epi32(S1.raw(), 0b00011011));  // EFGH

   __m128i tmp = _mm_alignr_epi8(S0.raw(), S1.raw(), 8);       // ABEF
   S1 = SIMD_4x32(_mm_blend_epi16(S1.raw(), S0.raw(), 0xF0));  // CDGH
   S0 = SIMD_4x32(tmp);
}

}  // namespace

BOTAN_FUNC_ISA("sha,sse4.1,ssse3")
void SHA_256::compress_digest_x86(digest_type& digest, std::span<const uint8_t> input_span, size_t blocks) {
   alignas(64) static const uint32_t K[] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
   };

   const uint8_t* input = input_span.data();

   SIMD_4x32 S0 = SIMD_4x32::load_le(&digest[0]);
   SIMD_4x32 S1 = SIMD_4x32::load_le(&digest[4]);

   sha256_permute_state(S0, S1);

   while(blocks > 0) {
      const auto S0_SAVE = S0;
      const auto S1_SAVE = S1;

      auto W0 = SIMD_4x32::load_be(input);
      auto W1 = SIMD_4x32::load_be(input + 16);
      auto W2 = SIMD_4x32::load_be(input + 32);
      auto W3 = SIMD_4x32::load_be(input + 48);

      sha256_rnds4(S0, S1, W0, SIMD_4x32::load_le(&K[0]));
      sha256_rnds4(S0, S1, W1, SIMD_4x32::load_le(&K[4]));
      sha256_rnds4(S0, S1, W2, SIMD_4x32::load_le(&K[8]));
      sha256_rnds4(S0, S1, W3, SIMD_4x32::load_le(&K[12]));

      W0 = SIMD_4x32(_mm_sha256msg1_epu32(W0.raw(), W1.raw()));
      W1 = SIMD_4x32(_mm_sha256msg1_epu32(W1.raw(), W2.raw()));

      for(size_t r = 4; r != 16; r += 4) {
         sha256_msg_exp(W2, W3, W0);
         sha256_rnds4(S0, S1, W0, SIMD_4x32::load_le(&K[4 * (r + 0)]));

         sha256_msg_exp(W3, W0, W1);
         sha256_rnds4(S0, S1, W1, SIMD_4x32::load_le(&K[4 * (r + 1)]));

         sha256_msg_exp(W0, W1, W2);
         sha256_rnds4(S0, S1, W2, SIMD_4x32::load_le(&K[4 * (r + 2)]));

         sha256_msg_exp(W1, W2, W3);
         sha256_rnds4(S0, S1, W3, SIMD_4x32::load_le(&K[4 * (r + 3)]));
      }

      // Add values back to state
      S0 += S0_SAVE;
      S1 += S1_SAVE;

      input += 64;
      blocks--;
   }

   sha256_permute_state(S1, S0);

   S0.store_le(&digest[0]);
   S1.store_le(&digest[4]);
}

}  // namespace Botan
