/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm3.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/rotate.h>
#include <botan/internal/simd_4x32.h>
#include <immintrin.h>

namespace Botan {

namespace {

BOTAN_FORCE_INLINE BOTAN_FN_ISA_AVX2_SM3 void sm3_permute_state_in(SIMD_4x32& S0, SIMD_4x32& S1) {
   S0 = SIMD_4x32(_mm_shuffle_epi32(S0.raw(), 0b10110001));  // CDAB
   S1 = SIMD_4x32(_mm_shuffle_epi32(S1.raw(), 0b00011011));  // EFGH

   const auto T = SIMD_4x32::alignr8(S0, S1);                                       // ABEF
   S1 = SIMD_4x32(_mm_blend_epi16(S1.rotr<19>().raw(), S0.rotr<9>().raw(), 0xF0));  // CDGH
   S0 = T;
}

BOTAN_FN_ISA_AVX2_SM3 inline void SM3_NI_next(SIMD_4x32& W0,
                                              const SIMD_4x32& W1,
                                              const SIMD_4x32& W2,
                                              const SIMD_4x32& W3) {
   auto X3 = SIMD_4x32(_mm_alignr_epi8(W1.raw(), W0.raw(), 12));  // W[3..6]
   auto X7 = SIMD_4x32(_mm_alignr_epi8(W2.raw(), W1.raw(), 12));  // W[7..10]
   auto X10 = SIMD_4x32::alignr8(W3, W2);                         // W[10..13]
   auto X13 = W3.template shift_elems_right<1>();                 // W[13..15] || 0

   auto P1_O = SIMD_4x32(_mm_sm3msg1_epi32(X7.raw(), X13.raw(), W0.raw()));
   W0 = SIMD_4x32(_mm_sm3msg2_epi32(P1_O.raw(), X3.raw(), X10.raw()));
}

template <size_t R>
BOTAN_FN_ISA_AVX2_SM3 inline void SM3_NI_Rx4(SIMD_4x32& S0, SIMD_4x32& S1, SIMD_4x32 W0, SIMD_4x32 W1) {
   const auto W0145 = SIMD_4x32(_mm_unpacklo_epi64(W0.raw(), W1.raw()));
   const auto W2367 = SIMD_4x32(_mm_unpackhi_epi64(W0.raw(), W1.raw()));

   S0 = SIMD_4x32(_mm_sm3rnds2_epi32(S0.raw(), S1.raw(), W0145.raw(), R));
   S1 = SIMD_4x32(_mm_sm3rnds2_epi32(S1.raw(), S0.raw(), W2367.raw(), R + 2));
}

}  // namespace

BOTAN_FN_ISA_AVX2_SM3 void SM3::compress_digest_x86(digest_type& digest,
                                                    std::span<const uint8_t> input,
                                                    size_t blocks) {
   auto S0 = SIMD_4x32::load_le(&digest[0]);  // NOLINT(*-container-data-pointer)
   auto S1 = SIMD_4x32::load_le(&digest[4]);
   sm3_permute_state_in(S0, S1);

   const uint8_t* data = input.data();

   while(blocks > 0) {
      SIMD_4x32 W0 = SIMD_4x32::load_be(&data[0]);  // NOLINT(*-container-data-pointer)
      SIMD_4x32 W1 = SIMD_4x32::load_be(&data[16]);
      SIMD_4x32 W2 = SIMD_4x32::load_be(&data[32]);
      SIMD_4x32 W3 = SIMD_4x32::load_be(&data[48]);

      const auto S0_save = S0;
      const auto S1_save = S1;

      data += block_bytes;
      blocks -= 1;

      SM3_NI_Rx4<0>(S1, S0, W0, W1);
      SM3_NI_next(W0, W1, W2, W3);

      SM3_NI_Rx4<4>(S1, S0, W1, W2);
      SM3_NI_next(W1, W2, W3, W0);

      SM3_NI_Rx4<8>(S1, S0, W2, W3);
      SM3_NI_next(W2, W3, W0, W1);

      SM3_NI_Rx4<12>(S1, S0, W3, W0);
      SM3_NI_next(W3, W0, W1, W2);

      SM3_NI_Rx4<16>(S1, S0, W0, W1);
      SM3_NI_next(W0, W1, W2, W3);

      SM3_NI_Rx4<20>(S1, S0, W1, W2);
      SM3_NI_next(W1, W2, W3, W0);

      SM3_NI_Rx4<24>(S1, S0, W2, W3);
      SM3_NI_next(W2, W3, W0, W1);

      SM3_NI_Rx4<28>(S1, S0, W3, W0);
      SM3_NI_next(W3, W0, W1, W2);

      SM3_NI_Rx4<32>(S1, S0, W0, W1);
      SM3_NI_next(W0, W1, W2, W3);

      SM3_NI_Rx4<36>(S1, S0, W1, W2);
      SM3_NI_next(W1, W2, W3, W0);

      SM3_NI_Rx4<40>(S1, S0, W2, W3);
      SM3_NI_next(W2, W3, W0, W1);

      SM3_NI_Rx4<44>(S1, S0, W3, W0);
      SM3_NI_next(W3, W0, W1, W2);

      SM3_NI_Rx4<48>(S1, S0, W0, W1);
      SM3_NI_next(W0, W1, W2, W3);

      SM3_NI_Rx4<52>(S1, S0, W1, W2);
      SM3_NI_Rx4<56>(S1, S0, W2, W3);
      SM3_NI_Rx4<60>(S1, S0, W3, W0);

      S0 ^= S0_save;
      S1 ^= S1_save;
   }

   // TODO do this with SIMD instead
   uint32_t T[8] = {0};
   S0.store_le(&T[0]);
   S1.store_le(&T[4]);

   digest[0] = T[3];
   digest[1] = T[2];
   digest[2] = rotr<23>(T[7]);
   digest[3] = rotr<23>(T[6]);
   digest[4] = T[1];
   digest[5] = T[0];
   digest[6] = rotr<13>(T[5]);
   digest[7] = rotr<13>(T[4]);
}

}  // namespace Botan
