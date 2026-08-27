/*
* (C) 2025 Jack Lloyd
* (C) 2026 Kagan Can Sit
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/simd_4x64.h>

namespace Botan {

namespace {

// NOLINTBEGIN(portability-simd-intrinsics)

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHA512 SIMD_4x64 sha512_msg1(const SIMD_4x64& x, const SIMD_4x64& w_lo) {
   return SIMD_4x64(_mm256_sha512msg1_epi64(x.raw(), _mm256_extracti128_si256(w_lo.raw(), 0)));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHA512 SIMD_4x64 sha512_msg2(const SIMD_4x64& x, const SIMD_4x64& y) {
   return SIMD_4x64(_mm256_sha512msg2_epi64(x.raw(), y.raw()));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHA512 void sha512_msg_expand(SIMD_4x64& m0,
                                                              SIMD_4x64& m1,
                                                              SIMD_4x64& m2,
                                                              SIMD_4x64& m3) {
   m3 = sha512_msg1(m3, m0);
   m2 += SIMD_4x64::permute_4x64<0b00111001>(SIMD_4x64(_mm256_blend_epi32(m0.raw(), m1.raw(), 0b0011)));
   m2 = sha512_msg2(m2, m1);
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_SHA512 void sha512_4rounds(SIMD_4x64& state0,
                                                           SIMD_4x64& state1,
                                                           const SIMD_4x64& msg,
                                                           const SIMD_4x64& K) {
   const auto tmp = msg + K;
   state0 = SIMD_4x64(_mm256_sha512rnds2_epi64(state0.raw(), state1.raw(), _mm256_extracti128_si256(tmp.raw(), 0)));
   state1 = SIMD_4x64(_mm256_sha512rnds2_epi64(state1.raw(), state0.raw(), _mm256_extracti128_si256(tmp.raw(), 1)));
}

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2 void permute_state(SIMD_4x64& state0, SIMD_4x64& state1) {
   __m256i s0 = _mm256_shuffle_epi32(state0.raw(), 0b01001110);
   __m256i s1 = _mm256_shuffle_epi32(state1.raw(), 0b01001110);
   const __m256i statet = s0;
   s0 = _mm256_permute2x128_si256(s0, s1, 0x13);
   s1 = _mm256_permute2x128_si256(statet, s1, 0x02);

   state0 = SIMD_4x64(s0);
   state1 = SIMD_4x64(s1);
}

// NOLINTEND(portability-simd-intrinsics)

}  // namespace

BOTAN_FN_ISA_SHA512
void SHA_512::compress_digest_x86(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   auto state0 = SIMD_4x64::load_le(digest.data());
   auto state1 = SIMD_4x64::load_le(digest.data() + 4);

   permute_state(state0, state1);

   const uint8_t* in = input.data();

   for(size_t i = 0; i != blocks; ++i) {
      const auto state0_save = state0;
      const auto state1_save = state1;

      auto m0 = SIMD_4x64::load_be(in + 0 * 32);
      auto m1 = SIMD_4x64::load_be(in + 1 * 32);
      auto m2 = SIMD_4x64::load_be(in + 2 * 32);
      auto m3 = SIMD_4x64::load_be(in + 3 * 32);

      sha512_4rounds(state0, state1, m0, SIMD_4x64::load_le(&SHA512_K[4 * 0]));
      sha512_4rounds(state0, state1, m1, SIMD_4x64::load_le(&SHA512_K[4 * 1]));
      m0 = sha512_msg1(m0, m1);

      for(size_t r = 2; r != 18; r += 4) {
         sha512_4rounds(state0, state1, m2, SIMD_4x64::load_le(&SHA512_K[4 * (r + 0)]));
         sha512_msg_expand(m2, m3, m0, m1);

         sha512_4rounds(state0, state1, m3, SIMD_4x64::load_le(&SHA512_K[4 * (r + 1)]));
         sha512_msg_expand(m3, m0, m1, m2);

         sha512_4rounds(state0, state1, m0, SIMD_4x64::load_le(&SHA512_K[4 * (r + 2)]));
         sha512_msg_expand(m0, m1, m2, m3);

         sha512_4rounds(state0, state1, m1, SIMD_4x64::load_le(&SHA512_K[4 * (r + 3)]));
         sha512_msg_expand(m1, m2, m3, m0);
      }

      sha512_4rounds(state0, state1, m2, SIMD_4x64::load_le(&SHA512_K[4 * 18]));
      sha512_4rounds(state0, state1, m3, SIMD_4x64::load_le(&SHA512_K[4 * 19]));

      state0 += state0_save;
      state1 += state1_save;

      in += 4 * 32;
   }

   permute_state(state0, state1);

   state0.store_le(digest.data());
   state1.store_le(digest.data() + 4);
}

}  // namespace Botan
