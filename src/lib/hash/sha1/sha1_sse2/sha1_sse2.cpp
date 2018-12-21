/*
* SHA-1 using SSE2
* Based on public domain code by Dean Gaudet
*    (http://arctic.org/~dean/crypto/sha1.html)
* (C) 2009-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sha160.h>
#include <botan/rotate.h>
#include <emmintrin.h>

namespace Botan {

namespace SHA1_SSE2_F {

namespace {

/*
* First 16 bytes just need byte swapping. Preparing just means
* adding in the round constants.
*/

#define prep00_15(P, W)                                      \
   do {                                                      \
      W = _mm_shufflehi_epi16(W, _MM_SHUFFLE(2, 3, 0, 1));   \
      W = _mm_shufflelo_epi16(W, _MM_SHUFFLE(2, 3, 0, 1));   \
      W = _mm_or_si128(_mm_slli_epi16(W, 8),                 \
                       _mm_srli_epi16(W, 8));                \
      P.u128 = _mm_add_epi32(W, K00_19);                     \
   } while(0)

/*
For each multiple of 4, t, we want to calculate this:

W[t+0] = rol(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
W[t+1] = rol(W[t-2] ^ W[t-7] ^ W[t-13] ^ W[t-15], 1);
W[t+2] = rol(W[t-1] ^ W[t-6] ^ W[t-12] ^ W[t-14], 1);
W[t+3] = rol(W[t]   ^ W[t-5] ^ W[t-11] ^ W[t-13], 1);

we'll actually calculate this:

W[t+0] = rol(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
W[t+1] = rol(W[t-2] ^ W[t-7] ^ W[t-13] ^ W[t-15], 1);
W[t+2] = rol(W[t-1] ^ W[t-6] ^ W[t-12] ^ W[t-14], 1);
W[t+3] = rol(  0    ^ W[t-5] ^ W[t-11] ^ W[t-13], 1);
W[t+3] ^= rol(W[t+0], 1);

the parameters are:

W0 = &W[t-16];
W1 = &W[t-12];
W2 = &W[t- 8];
W3 = &W[t- 4];

and on output:
prepared = W0 + K
W0 = W[t]..W[t+3]
*/

/* note that there is a step here where i want to do a rol by 1, which
* normally would look like this:
*
* r1 = psrld r0,$31
* r0 = pslld r0,$1
* r0 = por r0,r1
*
* but instead i do this:
*
* r1 = pcmpltd r0,zero
* r0 = paddd r0,r0
* r0 = psub r0,r1
*
* because pcmpltd and paddd are available in both MMX units on
* efficeon, pentium-m, and opteron but shifts are available in
* only one unit.
*/
#define prep(prep, XW0, XW1, XW2, XW3, K)                               \
   do {                                                                 \
      __m128i r0, r1, r2, r3;                                           \
                                                                        \
      /* load W[t-4] 16-byte aligned, and shift */                      \
      r3 = _mm_srli_si128((XW3), 4);                                    \
      r0 = (XW0);                                                       \
      /* get high 64-bits of XW0 into low 64-bits */                    \
      r1 = _mm_shuffle_epi32((XW0), _MM_SHUFFLE(1,0,3,2));              \
      /* load high 64-bits of r1 */                                     \
      r1 = _mm_unpacklo_epi64(r1, (XW1));                               \
      r2 = (XW2);                                                       \
                                                                        \
      r0 = _mm_xor_si128(r1, r0);                                       \
      r2 = _mm_xor_si128(r3, r2);                                       \
      r0 = _mm_xor_si128(r2, r0);                                       \
      /* unrotated W[t]..W[t+2] in r0 ... still need W[t+3] */          \
                                                                        \
      r2 = _mm_slli_si128(r0, 12);                                      \
      r1 = _mm_cmplt_epi32(r0, _mm_setzero_si128());                    \
      r0 = _mm_add_epi32(r0, r0);   /* shift left by 1 */               \
      r0 = _mm_sub_epi32(r0, r1);   /* r0 has W[t]..W[t+2] */           \
                                                                        \
      r3 = _mm_srli_epi32(r2, 30);                                      \
      r2 = _mm_slli_epi32(r2, 2);                                       \
                                                                        \
      r0 = _mm_xor_si128(r0, r3);                                       \
      r0 = _mm_xor_si128(r0, r2);   /* r0 now has W[t+3] */             \
                                                                        \
      (XW0) = r0;                                                       \
      (prep).u128 = _mm_add_epi32(r0, K);                               \
   } while(0)

/*
* SHA-160 F1 Function
*/
inline void F1(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += (D ^ (B & (C ^ D))) + msg + rotl<5>(A);
   B  = rotl<30>(B);
   }

/*
* SHA-160 F2 Function
*/
inline void F2(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += (B ^ C ^ D) + msg + rotl<5>(A);
   B  = rotl<30>(B);
   }

/*
* SHA-160 F3 Function
*/
inline void F3(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += ((B & C) | ((B | C) & D)) + msg + rotl<5>(A);
   B  = rotl<30>(B);
   }

/*
* SHA-160 F4 Function
*/
inline void F4(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg)
   {
   E += (B ^ C ^ D) + msg + rotl<5>(A);
   B  = rotl<30>(B);
   }

}

}

/*
* SHA-160 Compression Function using SSE for message expansion
*/
//static
BOTAN_FUNC_ISA("sse2")
void SHA_160::sse2_compress_n(secure_vector<uint32_t>& digest, const uint8_t input[], size_t blocks)
   {
   using namespace SHA1_SSE2_F;

   const __m128i K00_19 = _mm_set1_epi32(0x5A827999);
   const __m128i K20_39 = _mm_set1_epi32(0x6ED9EBA1);
   const __m128i K40_59 = _mm_set1_epi32(0x8F1BBCDC);
   const __m128i K60_79 = _mm_set1_epi32(0xCA62C1D6);

   uint32_t A = digest[0],
          B = digest[1],
          C = digest[2],
          D = digest[3],
          E = digest[4];

   const __m128i* input_mm = reinterpret_cast<const __m128i*>(input);

   for(size_t i = 0; i != blocks; ++i)
      {
      union v4si {
         uint32_t u32[4];
         __m128i u128;
         };

      v4si P0, P1, P2, P3;

      __m128i W0 = _mm_loadu_si128(&input_mm[0]);
      prep00_15(P0, W0);

      __m128i W1 = _mm_loadu_si128(&input_mm[1]);
      prep00_15(P1, W1);

      __m128i W2 = _mm_loadu_si128(&input_mm[2]);
      prep00_15(P2, W2);

      __m128i W3 = _mm_loadu_si128(&input_mm[3]);
      prep00_15(P3, W3);

      /*
      Using SSE4; slower on Core2 and Nehalem
      #define GET_P_32(P, i) _mm_extract_epi32(P.u128, i)

      Much slower on all tested platforms
      #define GET_P_32(P,i) _mm_cvtsi128_si32(_mm_srli_si128(P.u128, i*4))
      */

#define GET_P_32(P, i) P.u32[i]

      F1(A, B, C, D, E, GET_P_32(P0, 0));
      F1(E, A, B, C, D, GET_P_32(P0, 1));
      F1(D, E, A, B, C, GET_P_32(P0, 2));
      F1(C, D, E, A, B, GET_P_32(P0, 3));
      prep(P0, W0, W1, W2, W3, K00_19);

      F1(B, C, D, E, A, GET_P_32(P1, 0));
      F1(A, B, C, D, E, GET_P_32(P1, 1));
      F1(E, A, B, C, D, GET_P_32(P1, 2));
      F1(D, E, A, B, C, GET_P_32(P1, 3));
      prep(P1, W1, W2, W3, W0, K20_39);

      F1(C, D, E, A, B, GET_P_32(P2, 0));
      F1(B, C, D, E, A, GET_P_32(P2, 1));
      F1(A, B, C, D, E, GET_P_32(P2, 2));
      F1(E, A, B, C, D, GET_P_32(P2, 3));
      prep(P2, W2, W3, W0, W1, K20_39);

      F1(D, E, A, B, C, GET_P_32(P3, 0));
      F1(C, D, E, A, B, GET_P_32(P3, 1));
      F1(B, C, D, E, A, GET_P_32(P3, 2));
      F1(A, B, C, D, E, GET_P_32(P3, 3));
      prep(P3, W3, W0, W1, W2, K20_39);

      F1(E, A, B, C, D, GET_P_32(P0, 0));
      F1(D, E, A, B, C, GET_P_32(P0, 1));
      F1(C, D, E, A, B, GET_P_32(P0, 2));
      F1(B, C, D, E, A, GET_P_32(P0, 3));
      prep(P0, W0, W1, W2, W3, K20_39);

      F2(A, B, C, D, E, GET_P_32(P1, 0));
      F2(E, A, B, C, D, GET_P_32(P1, 1));
      F2(D, E, A, B, C, GET_P_32(P1, 2));
      F2(C, D, E, A, B, GET_P_32(P1, 3));
      prep(P1, W1, W2, W3, W0, K20_39);

      F2(B, C, D, E, A, GET_P_32(P2, 0));
      F2(A, B, C, D, E, GET_P_32(P2, 1));
      F2(E, A, B, C, D, GET_P_32(P2, 2));
      F2(D, E, A, B, C, GET_P_32(P2, 3));
      prep(P2, W2, W3, W0, W1, K40_59);

      F2(C, D, E, A, B, GET_P_32(P3, 0));
      F2(B, C, D, E, A, GET_P_32(P3, 1));
      F2(A, B, C, D, E, GET_P_32(P3, 2));
      F2(E, A, B, C, D, GET_P_32(P3, 3));
      prep(P3, W3, W0, W1, W2, K40_59);

      F2(D, E, A, B, C, GET_P_32(P0, 0));
      F2(C, D, E, A, B, GET_P_32(P0, 1));
      F2(B, C, D, E, A, GET_P_32(P0, 2));
      F2(A, B, C, D, E, GET_P_32(P0, 3));
      prep(P0, W0, W1, W2, W3, K40_59);

      F2(E, A, B, C, D, GET_P_32(P1, 0));
      F2(D, E, A, B, C, GET_P_32(P1, 1));
      F2(C, D, E, A, B, GET_P_32(P1, 2));
      F2(B, C, D, E, A, GET_P_32(P1, 3));
      prep(P1, W1, W2, W3, W0, K40_59);

      F3(A, B, C, D, E, GET_P_32(P2, 0));
      F3(E, A, B, C, D, GET_P_32(P2, 1));
      F3(D, E, A, B, C, GET_P_32(P2, 2));
      F3(C, D, E, A, B, GET_P_32(P2, 3));
      prep(P2, W2, W3, W0, W1, K40_59);

      F3(B, C, D, E, A, GET_P_32(P3, 0));
      F3(A, B, C, D, E, GET_P_32(P3, 1));
      F3(E, A, B, C, D, GET_P_32(P3, 2));
      F3(D, E, A, B, C, GET_P_32(P3, 3));
      prep(P3, W3, W0, W1, W2, K60_79);

      F3(C, D, E, A, B, GET_P_32(P0, 0));
      F3(B, C, D, E, A, GET_P_32(P0, 1));
      F3(A, B, C, D, E, GET_P_32(P0, 2));
      F3(E, A, B, C, D, GET_P_32(P0, 3));
      prep(P0, W0, W1, W2, W3, K60_79);

      F3(D, E, A, B, C, GET_P_32(P1, 0));
      F3(C, D, E, A, B, GET_P_32(P1, 1));
      F3(B, C, D, E, A, GET_P_32(P1, 2));
      F3(A, B, C, D, E, GET_P_32(P1, 3));
      prep(P1, W1, W2, W3, W0, K60_79);

      F3(E, A, B, C, D, GET_P_32(P2, 0));
      F3(D, E, A, B, C, GET_P_32(P2, 1));
      F3(C, D, E, A, B, GET_P_32(P2, 2));
      F3(B, C, D, E, A, GET_P_32(P2, 3));
      prep(P2, W2, W3, W0, W1, K60_79);

      F4(A, B, C, D, E, GET_P_32(P3, 0));
      F4(E, A, B, C, D, GET_P_32(P3, 1));
      F4(D, E, A, B, C, GET_P_32(P3, 2));
      F4(C, D, E, A, B, GET_P_32(P3, 3));
      prep(P3, W3, W0, W1, W2, K60_79);

      F4(B, C, D, E, A, GET_P_32(P0, 0));
      F4(A, B, C, D, E, GET_P_32(P0, 1));
      F4(E, A, B, C, D, GET_P_32(P0, 2));
      F4(D, E, A, B, C, GET_P_32(P0, 3));

      F4(C, D, E, A, B, GET_P_32(P1, 0));
      F4(B, C, D, E, A, GET_P_32(P1, 1));
      F4(A, B, C, D, E, GET_P_32(P1, 2));
      F4(E, A, B, C, D, GET_P_32(P1, 3));

      F4(D, E, A, B, C, GET_P_32(P2, 0));
      F4(C, D, E, A, B, GET_P_32(P2, 1));
      F4(B, C, D, E, A, GET_P_32(P2, 2));
      F4(A, B, C, D, E, GET_P_32(P2, 3));

      F4(E, A, B, C, D, GET_P_32(P3, 0));
      F4(D, E, A, B, C, GET_P_32(P3, 1));
      F4(C, D, E, A, B, GET_P_32(P3, 2));
      F4(B, C, D, E, A, GET_P_32(P3, 3));

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);

      input_mm += (64 / 16);
      }

#undef GET_P_32
   }

#undef prep00_15
#undef prep

}
