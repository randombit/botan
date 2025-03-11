/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_64.h>

#include <immintrin.h>

namespace Botan {

namespace {

BOTAN_FUNC_ISA_INLINE("sha512,avx2") void sha512_msg_expand(__m256i& m0, __m256i& m1, __m256i& m2, __m256i& m3) {
   m3 = _mm256_sha512msg1_epi64(m3, _mm256_extracti128_si256(m0, 0));
   m2 = _mm256_add_epi64(m2, _mm256_permute4x64_epi64(_mm256_blend_epi32(m0, m1, 3), 0b00111001));
   m2 = _mm256_sha512msg2_epi64(m2, m1);
}

BOTAN_FUNC_ISA_INLINE("sha512,avx2")
void sha512_4rounds(__m256i& state0, __m256i& state1, const __m256i msg, const __m256i K) {
   const auto tmp = _mm256_add_epi64(msg, K);
   state0 = _mm256_sha512rnds2_epi64(state0, state1, _mm256_extracti128_si256(tmp, 0));
   state1 = _mm256_sha512rnds2_epi64(state1, state0, _mm256_extracti128_si256(tmp, 1));
}

BOTAN_FUNC_ISA_INLINE("avx2") void permute_state(__m256i& state0, __m256i& state1) {
   state0 = _mm256_shuffle_epi32(state0, 0b01001110);
   state1 = _mm256_shuffle_epi32(state1, 0b01001110);
   auto statet = state0;
   state0 = _mm256_permute2x128_si256(state0, state1, 0x13);
   state1 = _mm256_permute2x128_si256(statet, state1, 0x02);
}

}  // namespace

BOTAN_FUNC_ISA("sha512,avx2")
void SHA_512::compress_digest_x86(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
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
      0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
   };

   const __m256i* K_mm = reinterpret_cast<const __m256i*>(K);

   const __m256i bswap_mask =
      _mm256_set_epi64x(0x08090a0b0c0d0e0f, 0x0001020304050607, 0x08090a0b0c0d0e0f, 0x0001020304050607);

   __m256i* digest_mm = reinterpret_cast<__m256i*>(digest.data());
   const __m256i* input_mm = reinterpret_cast<const __m256i*>(input.data());

   auto state0 = _mm256_loadu_si256(digest_mm);
   auto state1 = _mm256_loadu_si256(digest_mm + 1);

   permute_state(state0, state1);

   for(size_t i = 0; i != blocks; ++i) {
      const auto state0_save = state0;
      const auto state1_save = state1;

      auto m0 = _mm256_shuffle_epi8(_mm256_loadu_si256(input_mm + 0), bswap_mask);
      auto m1 = _mm256_shuffle_epi8(_mm256_loadu_si256(input_mm + 1), bswap_mask);
      auto m2 = _mm256_shuffle_epi8(_mm256_loadu_si256(input_mm + 2), bswap_mask);
      auto m3 = _mm256_shuffle_epi8(_mm256_loadu_si256(input_mm + 3), bswap_mask);

      sha512_4rounds(state0, state1, m0, _mm256_load_si256(&K_mm[0]));
      sha512_4rounds(state0, state1, m1, _mm256_load_si256(&K_mm[1]));
      m0 = _mm256_sha512msg1_epi64(m0, _mm256_extracti128_si256(m1, 0));

      for(size_t r = 2; r != 18; r += 4) {
         sha512_4rounds(state0, state1, m2, _mm256_load_si256(&K_mm[r + 0]));
         sha512_msg_expand(m2, m3, m0, m1);

         sha512_4rounds(state0, state1, m3, _mm256_load_si256(&K_mm[r + 1]));
         sha512_msg_expand(m3, m0, m1, m2);

         sha512_4rounds(state0, state1, m0, _mm256_load_si256(&K_mm[r + 2]));
         sha512_msg_expand(m0, m1, m2, m3);

         sha512_4rounds(state0, state1, m1, _mm256_load_si256(&K_mm[r + 3]));
         sha512_msg_expand(m1, m2, m3, m0);
      }

      sha512_4rounds(state0, state1, m2, _mm256_load_si256(&K_mm[18]));
      sha512_4rounds(state0, state1, m3, _mm256_load_si256(&K_mm[19]));

      state0 = _mm256_add_epi64(state0, state0_save);
      state1 = _mm256_add_epi64(state1, state1_save);

      input_mm += 4;
   }

   permute_state(state0, state1);

   _mm256_storeu_si256(digest_mm, state0);
   _mm256_storeu_si256(digest_mm + 1, state1);
}

}  // namespace Botan
