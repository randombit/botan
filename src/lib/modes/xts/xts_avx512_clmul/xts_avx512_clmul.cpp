/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/xts.h>

#include <botan/assert.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/poly_dbl.h>
#include <immintrin.h>

namespace Botan {

void BOTAN_FN_ISA_AVX512_CLMUL XTS_Mode::update_tweak_block_avx512_clmul(uint8_t tweak[], size_t BS, size_t N) {
   BOTAN_ASSERT_NOMSG(N > 0);

   if(BS == 16 && N % 8 == 0) {
      constexpr uint64_t P128 = 0x87;
      const __m512i poly = _mm512_set_epi64(0, P128, 0, P128, 0, P128, 0, P128);

      /*
      * We need to perform N doublings on each block.
      *
      * We can compute the carryless multiplication with any size. Here, curiously, the
      * constraint is that AVX2/AVX512 don't include an equivalent of psrldq (aka
      * _mm_srli_si128), which allows shifting 128-bit lanes by any number of bits.
      * Instead only byte-wide lane shifts are available, so we can only raise to powers
      * where N is a multiple of 8.
      */
      const size_t N_32 = N / 32;
      const size_t N_8 = (N - N_32 * 32) / 8;

      // Since we must anyway require N % 8 == 0, unrolling once is free and allows better ILP
      for(size_t i = 0; i != N; i += 8) {
         __m512i W0 = _mm512_loadu_si512(&tweak[i * BS]);
         __m512i W1 = _mm512_loadu_si512(&tweak[(i + 4) * BS]);

         for(size_t r = 0; r != N_32; ++r) {
            // (W << 32) ^ compute_carry(W >> 96)
            const auto C0 = _mm512_clmulepi64_epi128(_mm512_bsrli_epi128(W0, 12), poly, 0);
            const auto C1 = _mm512_clmulepi64_epi128(_mm512_bsrli_epi128(W1, 12), poly, 0);
            W0 = _mm512_xor_si512(_mm512_bslli_epi128(W0, 4), C0);
            W1 = _mm512_xor_si512(_mm512_bslli_epi128(W1, 4), C1);
         }

         for(size_t r = 0; r != N_8; ++r) {
            // (W << 8) ^ compute_carry(W >> 120)
            const auto C0 = _mm512_clmulepi64_epi128(_mm512_bsrli_epi128(W0, 15), poly, 0);
            const auto C1 = _mm512_clmulepi64_epi128(_mm512_bsrli_epi128(W1, 15), poly, 0);
            W0 = _mm512_xor_si512(_mm512_bslli_epi128(W0, 1), C0);
            W1 = _mm512_xor_si512(_mm512_bslli_epi128(W1, 1), C1);
         }

         _mm512_storeu_epi64(&tweak[i * BS], W0);
         _mm512_storeu_epi64(&tweak[(i + 4) * BS], W1);
      }
   } else {
      poly_double_n_le(tweak, &tweak[(N - 1) * BS], BS);
      xts_compute_tweak_block(tweak, BS, N);
   }
}

}  // namespace Botan
