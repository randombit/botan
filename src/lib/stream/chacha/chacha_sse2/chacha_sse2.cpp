/*
* SSE2 ChaCha
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <emmintrin.h>

namespace Botan {

//static
void ChaCha::chacha_sse2(byte output[64], const u32bit input[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

   const __m128i* input_mm = reinterpret_cast<const __m128i*>(input);

   const __m128i input0 = _mm_loadu_si128(input_mm);
   const __m128i input1 = _mm_loadu_si128(input_mm + 1);
   const __m128i input2 = _mm_loadu_si128(input_mm + 2);
   const __m128i input3 = _mm_loadu_si128(input_mm + 3);

   __m128i r0 = input0;
   __m128i r1 = input1;
   __m128i r2 = input2;
   __m128i r3 = input3;

#define mm_rotl(r, n) \
   _mm_or_si128(_mm_slli_epi32(r, n), _mm_srli_epi32(r, 32-n))

   for(size_t i = 0; i != rounds / 2; ++i)
      {
      r0 = _mm_add_epi32(r0, r1);
      r3 = _mm_xor_si128(r3, r0);
      r3 = mm_rotl(r3, 16);

      r2 = _mm_add_epi32(r2, r3);
      r1 = _mm_xor_si128(r1, r2);
      r1 = mm_rotl(r1, 12);

      r0 = _mm_add_epi32(r0, r1);
      r3 = _mm_xor_si128(r3, r0);
      r3 = mm_rotl(r3, 8);

      r2 = _mm_add_epi32(r2, r3);
      r1 = _mm_xor_si128(r1, r2);
      r1 = mm_rotl(r1, 7);

      r1 = _mm_shuffle_epi32(r1, _MM_SHUFFLE(0, 3, 2, 1));
      r2 = _mm_shuffle_epi32(r2, _MM_SHUFFLE(1, 0, 3, 2));
      r3 = _mm_shuffle_epi32(r3, _MM_SHUFFLE(2, 1, 0, 3));

      r0 = _mm_add_epi32(r0, r1);
      r3 = _mm_xor_si128(r3, r0);
      r3 = mm_rotl(r3, 16);

      r2 = _mm_add_epi32(r2, r3);
      r1 = _mm_xor_si128(r1, r2);
      r1 = mm_rotl(r1, 12);

      r0 = _mm_add_epi32(r0, r1);
      r3 = _mm_xor_si128(r3, r0);
      r3 = mm_rotl(r3, 8);

      r2 = _mm_add_epi32(r2, r3);
      r1 = _mm_xor_si128(r1, r2);
      r1 = mm_rotl(r1, 7);

      r1 = _mm_shuffle_epi32(r1, _MM_SHUFFLE(2, 1, 0, 3));
      r2 = _mm_shuffle_epi32(r2, _MM_SHUFFLE(1, 0, 3, 2));
      r3 = _mm_shuffle_epi32(r3, _MM_SHUFFLE(0, 3, 2, 1));
      }

#undef mm_rotl

   r0 = _mm_add_epi32(r0, input0);
   r1 = _mm_add_epi32(r1, input1);
   r2 = _mm_add_epi32(r2, input2);
   r3 = _mm_add_epi32(r3, input3);

   __m128i* output_mm = reinterpret_cast<__m128i*>(output);
   _mm_storeu_si128(output_mm    , r0);
   _mm_storeu_si128(output_mm + 1, r1);
   _mm_storeu_si128(output_mm + 2, r2);
   _mm_storeu_si128(output_mm + 3, r3);
   }

}
