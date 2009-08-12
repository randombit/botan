/*
* Serpent Sboxes in SSE2 form
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef SERPENT_SSE2_SBOXES_H__
#define SERPENT_SSE2_SBOXES_H__

#define SBoxE1(b0, b1, b2, b3)                          \
   do {                                                 \
      b3 = _mm_xor_si128(b3, b0);                       \
      __m128i b4 = b1;                                  \
      b1 = _mm_and_si128(b1, b3);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b1 = _mm_xor_si128(b1, b0);                       \
      b0 = _mm_or_si128(b0, b3);                        \
      b0 = _mm_xor_si128(b0, b4);                       \
      b4 = _mm_xor_si128(b4, b3);                       \
      b3 = _mm_xor_si128(b3, b2);                       \
      b2 = _mm_or_si128(b2, b1);                        \
      b2 = _mm_xor_si128(b2, b4);                       \
      b4 = _mm_andnot_si128(b4, _mm_set1_epi8(0xFF));   \
      b4 = _mm_or_si128(b4, b1);                        \
      b1 = _mm_xor_si128(b1, b3);                       \
      b1 = _mm_xor_si128(b1, b4);                       \
      b3 = _mm_or_si128(b3, b0);                        \
      b1 = _mm_xor_si128(b1, b3);                       \
      b4 = _mm_xor_si128(b4, b3);                       \
      b3 = b0;                                          \
      b0 = b1;                                          \
      b1 = b4;                                          \
   } while(0);

#define SBoxE2(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      b0 = _mm_andnot_si128(b0, _mm_set1_epi8(0xFF));   \
      b2 = _mm_andnot_si128(b2, _mm_set1_epi8(0xFF));   \
      __m128i b4 = b0;                                  \
      b0 = _mm_and_si128(b0, b1);                       \
      b2 = _mm_xor_si128(b2, b0);                       \
      b0 = _mm_or_si128(b0, b3);                        \
      b3 = _mm_xor_si128(b3, b2);                       \
      b1 = _mm_xor_si128(b1, b0);                       \
      b0 = _mm_xor_si128(b0, b4);                       \
      b4 = _mm_or_si128(b4, b1);                        \
      b1 = _mm_xor_si128(b1, b3);                       \
      b2 = _mm_or_si128(b2, b0);                        \
      b2 = _mm_and_si128(b2, b4);                       \
      b0 = _mm_xor_si128(b0, b1);                       \
      b1 = _mm_and_si128(b1, b2);                       \
      b1 = _mm_xor_si128(b1, b0);                       \
      b0 = _mm_and_si128(b0, b2);                       \
      b4 = _mm_xor_si128(b4, b0);                       \
      b0 = b2;                                          \
      b2 = b3;                                          \
      b3 = b1;                                          \
      b1 = b4;                                          \
      } while(0);

#define SBoxE3(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      __m128i b4 = b0;                                  \
      b0 = _mm_and_si128(b0, b2);                       \
      b0 = _mm_xor_si128(b0, b3);                       \
      b2 = _mm_xor_si128(b2, b1);                       \
      b2 = _mm_xor_si128(b2, b0);                       \
      b3 = _mm_or_si128(b3, b4);                        \
      b3 = _mm_xor_si128(b3, b1);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b1 = b3;                                          \
      b3 = _mm_or_si128(b3, b4);                        \
      b3 = _mm_xor_si128(b3, b0);                       \
      b0 = _mm_and_si128(b0, b1);                       \
      b4 = _mm_xor_si128(b4, b0);                       \
      b1 = _mm_xor_si128(b1, b3);                       \
      b1 = _mm_xor_si128(b1, b4);                       \
      b4 = _mm_andnot_si128(b4, _mm_set1_epi8(0xFF));   \
      b0 = b2;                                          \
      b2 = b1;                                          \
      b1 = b3;                                          \
      b3 = b4;                                          \
      } while(0);

#define SBoxE4(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      __m128i b4 = b0;                                  \
      b0 = _mm_or_si128(b0, b3);                        \
      b3 = _mm_xor_si128(b3, b1);                       \
      b1 = _mm_and_si128(b1, b4);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b2 = _mm_xor_si128(b2, b3);                       \
      b3 = _mm_and_si128(b3, b0);                       \
      b4 = _mm_or_si128(b4, b1);                        \
      b3 = _mm_xor_si128(b3, b4);                       \
      b0 = _mm_xor_si128(b0, b1);                       \
      b4 = _mm_and_si128(b4, b0);                       \
      b1 = _mm_xor_si128(b1, b3);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b1 = _mm_or_si128(b1, b0);                        \
      b1 = _mm_xor_si128(b1, b2);                       \
      b0 = _mm_xor_si128(b0, b3);                       \
      b2 = b1;                                          \
      b1 = _mm_or_si128(b1, b3);                        \
      b1 = _mm_xor_si128(b1, b0);                       \
      b0 = b1;                                          \
      b1 = b2;                                          \
      b2 = b3;                                          \
      b3 = b4;                                          \
      } while(0);

#define SBoxE5(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      b1 = _mm_xor_si128(b1, b3);                       \
      b3 = _mm_andnot_si128(b3, _mm_set1_epi8(0xFF));   \
      b2 = _mm_xor_si128(b2, b3);                       \
      b3 = _mm_xor_si128(b3, b0);                       \
      __m128i b4 = b1;                                  \
      b1 = _mm_and_si128(b1, b3);                       \
      b1 = _mm_xor_si128(b1, b2);                       \
      b4 = _mm_xor_si128(b4, b3);                       \
      b0 = _mm_xor_si128(b0, b4);                       \
      b2 = _mm_and_si128(b2, b4);                       \
      b2 = _mm_xor_si128(b2, b0);                       \
      b0 = _mm_and_si128(b0, b1);                       \
      b3 = _mm_xor_si128(b3, b0);                       \
      b4 = _mm_or_si128(b4, b1);                        \
      b4 = _mm_xor_si128(b4, b0);                       \
      b0 = _mm_or_si128(b0, b3);                        \
      b0 = _mm_xor_si128(b0, b2);                       \
      b2 = _mm_and_si128(b2, b3);                       \
      b0 = _mm_andnot_si128(b0, _mm_set1_epi8(0xFF));   \
      b4 = _mm_xor_si128(b4, b2);                       \
      b2 = b0;                                          \
      b0 = b1;                                          \
      b1 = b4;                                          \
      } while(0);

#define SBoxE6(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      b0 = _mm_xor_si128(b0, b1);                       \
      b1 = _mm_xor_si128(b1, b3);                       \
      b3 = _mm_andnot_si128(b3, _mm_set1_epi8(0xFF));   \
      __m128i b4 = b1;                                  \
      b1 = _mm_and_si128(b1, b0);                       \
      b2 = _mm_xor_si128(b2, b3);                       \
      b1 = _mm_xor_si128(b1, b2);                       \
      b2 = _mm_or_si128(b2, b4);                        \
      b4 = _mm_xor_si128(b4, b3);                       \
      b3 = _mm_and_si128(b3, b1);                       \
      b3 = _mm_xor_si128(b3, b0);                       \
      b4 = _mm_xor_si128(b4, b1);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b2 = _mm_xor_si128(b2, b0);                       \
      b0 = _mm_and_si128(b0, b3);                       \
      b2 = _mm_andnot_si128(b2, _mm_set1_epi8(0xFF));   \
      b0 = _mm_xor_si128(b0, b4);                       \
      b4 = _mm_or_si128(b4, b3);                        \
      b4 = _mm_xor_si128(b4, b2);                       \
      b2 = b0;                                          \
      b0 = b1;                                          \
      b1 = b3;                                          \
      b3 = b4;                                          \
      } while(0);

#define SBoxE7(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      b2 = _mm_andnot_si128(b2, _mm_set1_epi8(0xFF));   \
      __m128i b4 = b3;                                  \
      b3 = _mm_and_si128(b3, b0);                       \
      b0 = _mm_xor_si128(b0, b4);                       \
      b3 = _mm_xor_si128(b3, b2);                       \
      b2 = _mm_or_si128(b2, b4);                        \
      b1 = _mm_xor_si128(b1, b3);                       \
      b2 = _mm_xor_si128(b2, b0);                       \
      b0 = _mm_or_si128(b0, b1);                        \
      b2 = _mm_xor_si128(b2, b1);                       \
      b4 = _mm_xor_si128(b4, b0);                       \
      b0 = _mm_or_si128(b0, b3);                        \
      b0 = _mm_xor_si128(b0, b2);                       \
      b4 = _mm_xor_si128(b4, b3);                       \
      b4 = _mm_xor_si128(b4, b0);                       \
      b3 = _mm_andnot_si128(b3, _mm_set1_epi8(0xFF));   \
      b2 = _mm_and_si128(b2, b4);                       \
      b3 = _mm_xor_si128(b3, b2);                       \
      b2 = b4;                                          \
      } while(0);

#define SBoxE8(b0, b1, b2, b3)                          \
   do                                                   \
      {                                                 \
      __m128i b4 = b1;                                  \
      b1 = _mm_or_si128(b1, b2);                        \
      b1 = _mm_xor_si128(b1, b3);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b2 = _mm_xor_si128(b2, b1);                       \
      b3 = _mm_or_si128(b3, b4);                        \
      b3 = _mm_and_si128(b3, b0);                       \
      b4 = _mm_xor_si128(b4, b2);                       \
      b3 = _mm_xor_si128(b3, b1);                       \
      b1 = _mm_or_si128(b1, b4);                        \
      b1 = _mm_xor_si128(b1, b0);                       \
      b0 = _mm_or_si128(b0, b4);                        \
      b0 = _mm_xor_si128(b0, b2);                       \
      b1 = _mm_xor_si128(b1, b4);                       \
      b2 = _mm_xor_si128(b2, b1);                       \
      b1 = _mm_and_si128(b1, b0);                       \
      b1 = _mm_xor_si128(b1, b4);                       \
      b2 = _mm_andnot_si128(b2, _mm_set1_epi8(0xFF));   \
      b2 = _mm_or_si128(b2, b0);                        \
      b4 = _mm_xor_si128(b4, b2);                       \
      b2 = b1;                                          \
      b1 = b3;                                          \
      b3 = b0;                                          \
      b0 = b4;                                          \
      } while(0);

#endif
