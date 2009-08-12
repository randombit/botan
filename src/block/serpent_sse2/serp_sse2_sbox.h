/*
* Serpent Sboxes in SSE2 form
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef SERPENT_SSE2_SBOXES_H__
#define SERPENT_SSE2_SBOXES_H__

#define SBoxE1(B0, B1, B2, B3)                    \
   do {                                           \
      B3 = _mm_xor_si128(B3, B0);                 \
      __m128i B4 = B1;                            \
      B1 = _mm_and_si128(B1, B3);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B1 = _mm_xor_si128(B1, B0);                 \
      B0 = _mm_or_si128(B0, B3);                  \
      B0 = _mm_xor_si128(B0, B4);                 \
      B4 = _mm_xor_si128(B4, B3);                 \
      B3 = _mm_xor_si128(B3, B2);                 \
      B2 = _mm_or_si128(B2, B1);                  \
      B2 = _mm_xor_si128(B2, B4);                 \
      B4 = _mm_xor_si128(B4, all_ones);           \
      B4 = _mm_or_si128(B4, B1);                  \
      B1 = _mm_xor_si128(B1, B3);                 \
      B1 = _mm_xor_si128(B1, B4);                 \
      B3 = _mm_or_si128(B3, B0);                  \
      B1 = _mm_xor_si128(B1, B3);                 \
      B4 = _mm_xor_si128(B4, B3);                 \
      B3 = B0;                                    \
      B0 = B1;                                    \
      B1 = B4;                                    \
   } while(0);

#define SBoxE2(B0, B1, B2, B3)                    \
   do {                                           \
      B0 = _mm_xor_si128(B0, all_ones);           \
      B2 = _mm_xor_si128(B2, all_ones);           \
      __m128i B4 = B0;                            \
      B0 = _mm_and_si128(B0, B1);                 \
      B2 = _mm_xor_si128(B2, B0);                 \
      B0 = _mm_or_si128(B0, B3);                  \
      B3 = _mm_xor_si128(B3, B2);                 \
      B1 = _mm_xor_si128(B1, B0);                 \
      B0 = _mm_xor_si128(B0, B4);                 \
      B4 = _mm_or_si128(B4, B1);                  \
      B1 = _mm_xor_si128(B1, B3);                 \
      B2 = _mm_or_si128(B2, B0);                  \
      B2 = _mm_and_si128(B2, B4);                 \
      B0 = _mm_xor_si128(B0, B1);                 \
      B1 = _mm_and_si128(B1, B2);                 \
      B1 = _mm_xor_si128(B1, B0);                 \
      B0 = _mm_and_si128(B0, B2);                 \
      B4 = _mm_xor_si128(B4, B0);                 \
      B0 = B2;                                    \
      B2 = B3;                                    \
      B3 = B1;                                    \
      B1 = B4;                                    \
   } while(0);

#define SBoxE3(B0, B1, B2, B3)                    \
   do {                                           \
      __m128i B4 = B0;                            \
      B0 = _mm_and_si128(B0, B2);                 \
      B0 = _mm_xor_si128(B0, B3);                 \
      B2 = _mm_xor_si128(B2, B1);                 \
      B2 = _mm_xor_si128(B2, B0);                 \
      B3 = _mm_or_si128(B3, B4);                  \
      B3 = _mm_xor_si128(B3, B1);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B1 = B3;                                    \
      B3 = _mm_or_si128(B3, B4);                  \
      B3 = _mm_xor_si128(B3, B0);                 \
      B0 = _mm_and_si128(B0, B1);                 \
      B4 = _mm_xor_si128(B4, B0);                 \
      B1 = _mm_xor_si128(B1, B3);                 \
      B1 = _mm_xor_si128(B1, B4);                 \
      B4 = _mm_xor_si128(B4, all_ones);           \
      B0 = B2;                                    \
      B2 = B1;                                    \
      B1 = B3;                                    \
      B3 = B4;                                    \
   } while(0);

#define SBoxE4(B0, B1, B2, B3)                    \
   do {                                           \
      __m128i B4 = B0;                            \
      B0 = _mm_or_si128(B0, B3);                  \
      B3 = _mm_xor_si128(B3, B1);                 \
      B1 = _mm_and_si128(B1, B4);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B2 = _mm_xor_si128(B2, B3);                 \
      B3 = _mm_and_si128(B3, B0);                 \
      B4 = _mm_or_si128(B4, B1);                  \
      B3 = _mm_xor_si128(B3, B4);                 \
      B0 = _mm_xor_si128(B0, B1);                 \
      B4 = _mm_and_si128(B4, B0);                 \
      B1 = _mm_xor_si128(B1, B3);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B1 = _mm_or_si128(B1, B0);                  \
      B1 = _mm_xor_si128(B1, B2);                 \
      B0 = _mm_xor_si128(B0, B3);                 \
      B2 = B1;                                    \
      B1 = _mm_or_si128(B1, B3);                  \
      B0 = _mm_xor_si128(B0, B1);                 \
      B1 = B2;                                    \
      B2 = B3;                                    \
      B3 = B4;                                    \
   } while(0);

#define SBoxE5(B0, B1, B2, B3)                    \
   do {                                           \
      B1 = _mm_xor_si128(B1, B3);                 \
      B3 = _mm_xor_si128(B3, all_ones);           \
      B2 = _mm_xor_si128(B2, B3);                 \
      B3 = _mm_xor_si128(B3, B0);                 \
      __m128i B4 = B1;                            \
      B1 = _mm_and_si128(B1, B3);                 \
      B1 = _mm_xor_si128(B1, B2);                 \
      B4 = _mm_xor_si128(B4, B3);                 \
      B0 = _mm_xor_si128(B0, B4);                 \
      B2 = _mm_and_si128(B2, B4);                 \
      B2 = _mm_xor_si128(B2, B0);                 \
      B0 = _mm_and_si128(B0, B1);                 \
      B3 = _mm_xor_si128(B3, B0);                 \
      B4 = _mm_or_si128(B4, B1);                  \
      B4 = _mm_xor_si128(B4, B0);                 \
      B0 = _mm_or_si128(B0, B3);                  \
      B0 = _mm_xor_si128(B0, B2);                 \
      B2 = _mm_and_si128(B2, B3);                 \
      B0 = _mm_xor_si128(B0, all_ones);           \
      B4 = _mm_xor_si128(B4, B2);                 \
      B2 = B0;                                    \
      B0 = B1;                                    \
      B1 = B4;                                    \
   } while(0);

#define SBoxE6(B0, B1, B2, B3)                    \
   do {                                           \
      B0 = _mm_xor_si128(B0, B1);                 \
      B1 = _mm_xor_si128(B1, B3);                 \
      B3 = _mm_xor_si128(B3, all_ones);           \
      __m128i B4 = B1;                            \
      B1 = _mm_and_si128(B1, B0);                 \
      B2 = _mm_xor_si128(B2, B3);                 \
      B1 = _mm_xor_si128(B1, B2);                 \
      B2 = _mm_or_si128(B2, B4);                  \
      B4 = _mm_xor_si128(B4, B3);                 \
      B3 = _mm_and_si128(B3, B1);                 \
      B3 = _mm_xor_si128(B3, B0);                 \
      B4 = _mm_xor_si128(B4, B1);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B2 = _mm_xor_si128(B2, B0);                 \
      B0 = _mm_and_si128(B0, B3);                 \
      B2 = _mm_xor_si128(B2, all_ones);           \
      B0 = _mm_xor_si128(B0, B4);                 \
      B4 = _mm_or_si128(B4, B3);                  \
      B4 = _mm_xor_si128(B4, B2);                 \
      B2 = B0;                                    \
      B0 = B1;                                    \
      B1 = B3;                                    \
      B3 = B4;                                    \
   } while(0);

#define SBoxE7(B0, B1, B2, B3)                    \
   do {                                           \
      B2 = _mm_xor_si128(B2, all_ones);           \
      __m128i B4 = B3;                            \
      B3 = _mm_and_si128(B3, B0);                 \
      B0 = _mm_xor_si128(B0, B4);                 \
      B3 = _mm_xor_si128(B3, B2);                 \
      B2 = _mm_or_si128(B2, B4);                  \
      B1 = _mm_xor_si128(B1, B3);                 \
      B2 = _mm_xor_si128(B2, B0);                 \
      B0 = _mm_or_si128(B0, B1);                  \
      B2 = _mm_xor_si128(B2, B1);                 \
      B4 = _mm_xor_si128(B4, B0);                 \
      B0 = _mm_or_si128(B0, B3);                  \
      B0 = _mm_xor_si128(B0, B2);                 \
      B4 = _mm_xor_si128(B4, B3);                 \
      B4 = _mm_xor_si128(B4, B0);                 \
      B3 = _mm_xor_si128(B3, all_ones);           \
      B2 = _mm_and_si128(B2, B4);                 \
      B3 = _mm_xor_si128(B3, B2);                 \
      B2 = B4;                                    \
   } while(0);

#define SBoxE8(B0, B1, B2, B3)                    \
   do {                                           \
      __m128i B4 = B1;                            \
      B1 = _mm_or_si128(B1, B2);                  \
      B1 = _mm_xor_si128(B1, B3);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B2 = _mm_xor_si128(B2, B1);                 \
      B3 = _mm_or_si128(B3, B4);                  \
      B3 = _mm_and_si128(B3, B0);                 \
      B4 = _mm_xor_si128(B4, B2);                 \
      B3 = _mm_xor_si128(B3, B1);                 \
      B1 = _mm_or_si128(B1, B4);                  \
      B1 = _mm_xor_si128(B1, B0);                 \
      B0 = _mm_or_si128(B0, B4);                  \
      B0 = _mm_xor_si128(B0, B2);                 \
      B1 = _mm_xor_si128(B1, B4);                 \
      B2 = _mm_xor_si128(B2, B1);                 \
      B1 = _mm_and_si128(B1, B0);                 \
      B1 = _mm_xor_si128(B1, B4);                 \
      B2 = _mm_xor_si128(B2, all_ones);           \
      B2 = _mm_or_si128(B2, B0);                  \
      B4 = _mm_xor_si128(B4, B2);                 \
      B2 = B1;                                    \
      B1 = B3;                                    \
      B3 = B0;                                    \
      B0 = B4;                                    \
   } while(0);

#endif
