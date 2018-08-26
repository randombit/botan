/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha.h>
#include <immintrin.h>

namespace Botan {

//static
BOTAN_FUNC_ISA("avx2")
void ChaCha::chacha_avx2_x8(uint8_t output[64*8], uint32_t input[16], size_t rounds)
   {
   BOTAN_ASSERT(rounds % 2 == 0, "Valid rounds");

   const __m128i* input_mm = reinterpret_cast<const __m128i*>(input);
   __m256i* output_mm = reinterpret_cast<__m256i*>(output);

   const __m256i input0 = _mm256_broadcastsi128_si256(_mm_loadu_si128(input_mm));
   const __m256i input1 = _mm256_broadcastsi128_si256(_mm_loadu_si128(input_mm + 1));
   const __m256i input2 = _mm256_broadcastsi128_si256(_mm_loadu_si128(input_mm + 2));
   const __m256i input3 = _mm256_broadcastsi128_si256(_mm_loadu_si128(input_mm + 3));

   const __m256i CTR0 = _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 4);
   const __m256i CTR1 = _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 5);
   const __m256i CTR2 = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 6);
   const __m256i CTR3 = _mm256_set_epi32(0, 0, 0, 3, 0, 0, 0, 7);

   const __m256i shuf_rotl_16 = _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
                                                13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
   const __m256i shuf_rotl_8 = _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
                                               14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

#define mm_rotl(r, n) \
   _mm256_or_si256(_mm256_slli_epi32(r, n), _mm256_srli_epi32(r, 32-n))

   __m256i X0_0 = input0;
   __m256i X0_1 = input1;
   __m256i X0_2 = input2;
   __m256i X0_3 = _mm256_add_epi64(input3, CTR0);

   __m256i X1_0 = input0;
   __m256i X1_1 = input1;
   __m256i X1_2 = input2;
   __m256i X1_3 = _mm256_add_epi64(input3, CTR1);

   __m256i X2_0 = input0;
   __m256i X2_1 = input1;
   __m256i X2_2 = input2;
   __m256i X2_3 = _mm256_add_epi64(input3, CTR2);

   __m256i X3_0 = input0;
   __m256i X3_1 = input1;
   __m256i X3_2 = input2;
   __m256i X3_3 = _mm256_add_epi64(input3, CTR3);

   for(size_t r = 0; r != rounds / 2; ++r)
      {
      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = _mm256_shuffle_epi8(X0_3, shuf_rotl_16);
      X1_3 = _mm256_shuffle_epi8(X1_3, shuf_rotl_16);
      X2_3 = _mm256_shuffle_epi8(X2_3, shuf_rotl_16);
      X3_3 = _mm256_shuffle_epi8(X3_3, shuf_rotl_16);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = mm_rotl(X0_1, 12);
      X1_1 = mm_rotl(X1_1, 12);
      X2_1 = mm_rotl(X2_1, 12);
      X3_1 = mm_rotl(X3_1, 12);

      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = _mm256_shuffle_epi8(X0_3, shuf_rotl_8);
      X1_3 = _mm256_shuffle_epi8(X1_3, shuf_rotl_8);
      X2_3 = _mm256_shuffle_epi8(X2_3, shuf_rotl_8);
      X3_3 = _mm256_shuffle_epi8(X3_3, shuf_rotl_8);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = mm_rotl(X0_1, 7);
      X1_1 = mm_rotl(X1_1, 7);
      X2_1 = mm_rotl(X2_1, 7);
      X3_1 = mm_rotl(X3_1, 7);

      X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(0, 3, 2, 1));
      X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
      X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(2, 1, 0, 3));

      X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(0, 3, 2, 1));
      X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
      X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(2, 1, 0, 3));

      X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(0, 3, 2, 1));
      X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
      X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(2, 1, 0, 3));

      X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(0, 3, 2, 1));
      X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
      X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(2, 1, 0, 3));

      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = _mm256_shuffle_epi8(X0_3, shuf_rotl_16);
      X1_3 = _mm256_shuffle_epi8(X1_3, shuf_rotl_16);
      X2_3 = _mm256_shuffle_epi8(X2_3, shuf_rotl_16);
      X3_3 = _mm256_shuffle_epi8(X3_3, shuf_rotl_16);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = mm_rotl(X0_1, 12);
      X1_1 = mm_rotl(X1_1, 12);
      X2_1 = mm_rotl(X2_1, 12);
      X3_1 = mm_rotl(X3_1, 12);

      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = _mm256_shuffle_epi8(X0_3, shuf_rotl_8);
      X1_3 = _mm256_shuffle_epi8(X1_3, shuf_rotl_8);
      X2_3 = _mm256_shuffle_epi8(X2_3, shuf_rotl_8);
      X3_3 = _mm256_shuffle_epi8(X3_3, shuf_rotl_8);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = mm_rotl(X0_1, 7);
      X1_1 = mm_rotl(X1_1, 7);
      X2_1 = mm_rotl(X2_1, 7);
      X3_1 = mm_rotl(X3_1, 7);

      X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(2, 1, 0, 3));
      X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
      X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(0, 3, 2, 1));

      X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(2, 1, 0, 3));
      X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
      X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(0, 3, 2, 1));

      X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(2, 1, 0, 3));
      X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
      X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(0, 3, 2, 1));

      X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(2, 1, 0, 3));
      X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
      X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(0, 3, 2, 1));
      }

   X0_0 = _mm256_add_epi32(X0_0, input0);
   X0_1 = _mm256_add_epi32(X0_1, input1);
   X0_2 = _mm256_add_epi32(X0_2, input2);
   X0_3 = _mm256_add_epi32(X0_3, input3);
   X0_3 = _mm256_add_epi64(X0_3, CTR0);

   X1_0 = _mm256_add_epi32(X1_0, input0);
   X1_1 = _mm256_add_epi32(X1_1, input1);
   X1_2 = _mm256_add_epi32(X1_2, input2);
   X1_3 = _mm256_add_epi32(X1_3, input3);
   X1_3 = _mm256_add_epi64(X1_3, CTR1);

   X2_0 = _mm256_add_epi32(X2_0, input0);
   X2_1 = _mm256_add_epi32(X2_1, input1);
   X2_2 = _mm256_add_epi32(X2_2, input2);
   X2_3 = _mm256_add_epi32(X2_3, input3);
   X2_3 = _mm256_add_epi64(X2_3, CTR2);

   X3_0 = _mm256_add_epi32(X3_0, input0);
   X3_1 = _mm256_add_epi32(X3_1, input1);
   X3_2 = _mm256_add_epi32(X3_2, input2);
   X3_3 = _mm256_add_epi32(X3_3, input3);
   X3_3 = _mm256_add_epi64(X3_3, CTR3);

   _mm256_storeu_si256(output_mm     , _mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  1, _mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  2, _mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  3, _mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  4, _mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  5, _mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  6, _mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)));
   _mm256_storeu_si256(output_mm +  7, _mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)));

   _mm256_storeu_si256(output_mm +  8, _mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm +  9, _mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm + 10, _mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm + 11, _mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm + 12, _mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm + 13, _mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm + 14, _mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)));
   _mm256_storeu_si256(output_mm + 15, _mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)));

#undef mm_rotl

   input[12] += 8;
   if(input[12] < 8)
      input[13]++;

   }
}
