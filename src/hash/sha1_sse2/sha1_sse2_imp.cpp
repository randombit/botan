/* this code is public domain.

 * dean gaudet <dean@arctic.org>

 * this code was inspired by this paper:

 *     SHA: A Design for Parallel Architectures?
 *     Antoon Bosselaers, Ren´e Govaerts and Joos Vandewalle
 *     <http://www.esat.kuleuven.ac.be/~cosicart/pdf/AB-9700.pdf>

 * more information available on this implementation here:

 * 	http://arctic.org/~dean/crypto/sha1.html

 * version: 2
 */

/*
 * Lightly modified for Botan, tested under GCC 4.1.1 and ICC 9.1
 * on a Linux/Core2 system.

 */
#include <botan/sha1_sse2.h>
#include <xmmintrin.h>

namespace Botan {

namespace {

typedef union {
   u32bit u32[4];
   __m128i u128;
   } v4si __attribute__((aligned(16)));

static const v4si K00_19 = { { 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999 } };
static const v4si K20_39 = { { 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1 } };
static const v4si K40_59 = { { 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc } };
static const v4si K60_79 = { { 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6 } };

#define UNALIGNED 1
#if UNALIGNED
#define load(p)	_mm_loadu_si128(p)
#else
#define load(p) (*p)
#endif


/*
the first 16 bytes only need byte swapping

prepared points to 4x u32bit, 16-byte aligned

W points to the 4 dwords which need preparing --
and is overwritten with the swapped bytes
*/
#define prep00_15(prep, W)	do { 					\
		__m128i r1, r2;						\
									\
		r1 = (W);						\
		if (1) {						\
		r1 = _mm_shufflehi_epi16(r1, _MM_SHUFFLE(2, 3, 0, 1));	\
		r1 = _mm_shufflelo_epi16(r1, _MM_SHUFFLE(2, 3, 0, 1));	\
		r2 = _mm_slli_epi16(r1, 8);				\
		r1 = _mm_srli_epi16(r1, 8);				\
		r1 = _mm_or_si128(r1, r2);				\
		(W) = r1;						\
		}							\
		(prep).u128 = _mm_add_epi32(K00_19.u128, r1);		\
	} while(0)



/*
for each multiple of 4, t, we want to calculate this:

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
* because pcmpltd and paddd are availabe in both MMX units on
* efficeon, pentium-m, and opteron but shifts are available in
* only one unit.
*/
#define prep(prep, XW0, XW1, XW2, XW3, K) do { 					\
		__m128i r0, r1, r2, r3;						\
										\
		/* load W[t-4] 16-byte aligned, and shift */			\
		r3 = _mm_srli_si128((XW3), 4);					\
		r0 = (XW0);							\
		/* get high 64-bits of XW0 into low 64-bits */			\
		r1 = _mm_shuffle_epi32((XW0), _MM_SHUFFLE(1,0,3,2));		\
		/* load high 64-bits of r1 */					\
		r1 = _mm_unpacklo_epi64(r1, (XW1));				\
		r2 = (XW2);							\
										\
		r0 = _mm_xor_si128(r1, r0);					\
		r2 = _mm_xor_si128(r3, r2);					\
		r0 = _mm_xor_si128(r2, r0);					\
		/* unrotated W[t]..W[t+2] in r0 ... still need W[t+3] */	\
										\
		r2 = _mm_slli_si128(r0, 12);					\
		r1 = _mm_cmplt_epi32(r0, _mm_setzero_si128());			\
		r0 = _mm_add_epi32(r0, r0);	/* shift left by 1 */		\
		r0 = _mm_sub_epi32(r0, r1);	/* r0 has W[t]..W[t+2] */	\
										\
		r3 = _mm_srli_epi32(r2, 30);					\
		r2 = _mm_slli_epi32(r2, 2);					\
										\
		r0 = _mm_xor_si128(r0, r3);					\
		r0 = _mm_xor_si128(r0, r2);	/* r0 now has W[t+3] */		\
										\
		(XW0) = r0;							\
		(prep).u128 = _mm_add_epi32(r0, (K).u128);			\
	} while(0)


static inline u32bit rol(u32bit src, u32bit amt)
   {
   /* gcc and icc appear to turn this into a rotate */
   return (src << amt) | (src >> (32 - amt));
   }


static inline u32bit f00_19(u32bit x, u32bit y, u32bit z)
   {
   /* FIPS 180-2 says this: (x & y) ^ (~x & z)
   * but we can calculate it in fewer steps.
   */
   return ((y ^ z) & x) ^ z;
   }


static inline u32bit f20_39(u32bit x, u32bit y, u32bit z)
   {
   return (x ^ z) ^ y;
   }


static inline u32bit f40_59(u32bit x, u32bit y, u32bit z)
   {
   /* FIPS 180-2 says this: (x & y) ^ (x & z) ^ (y & z)
   * but we can calculate it in fewer steps.
   */
   return (x & z) | ((x | z) & y);
   }


static inline u32bit f60_79(u32bit x, u32bit y, u32bit z)
   {
   return f20_39(x, y, z);
   }

#define step(nn_mm, xa, xb, xc, xd, xe, xt, input) do {					\
		(xt) = (input) + f##nn_mm((xb), (xc), (xd));				\
		(xb) = rol((xb), 30); 							\
		(xt) += ((xe) + rol((xa), 5));						\
	} while(0)

}

extern "C" void botan_sha1_sse2_compress(u32bit H[5],
                                         const u32bit* inputu)
   {
   const __m128i *  input = (const __m128i *)inputu;
   __m128i W0, W1, W2, W3;
   v4si prep0, prep1, prep2;
   u32bit a, b, c, d, e, t;

   a = H[0];
   b = H[1];
   c = H[2];
   d = H[3];
   e = H[4];

   /* i've tried arranging the SSE2 code to be 4, 8, 12, and 16
   * steps ahead of the integer code.  12 steps ahead seems
   * to produce the best performance. -dean
   */
   W0 = load(&input[0]);
   prep00_15(prep0, W0);				/* prepare for 00 through 03 */
   W1 = load(&input[1]);
   prep00_15(prep1, W1);				/* prepare for 04 through 07 */
   W2 = load(&input[2]);
   prep00_15(prep2, W2);				/* prepare for 08 through 11 */

   W3 = load(&input[3]);
   step(00_19, a, b, c, d, e, t, prep0.u32[0]);	/* 00 */
   step(00_19, t, a, b, c, d, e, prep0.u32[1]);	/* 01 */
   step(00_19, e, t, a, b, c, d, prep0.u32[2]);	/* 02 */
   step(00_19, d, e, t, a, b, c, prep0.u32[3]);	/* 03 */
   prep00_15(prep0, W3);
   step(00_19, c, d, e, t, a, b, prep1.u32[0]);	/* 04 */
   step(00_19, b, c, d, e, t, a, prep1.u32[1]);	/* 05 */
   step(00_19, a, b, c, d, e, t, prep1.u32[2]);	/* 06 */
   step(00_19, t, a, b, c, d, e, prep1.u32[3]);	/* 07 */
   prep(prep1, W0, W1, W2, W3, K00_19);		/* prepare for 16 through 19 */
   step(00_19, e, t, a, b, c, d, prep2.u32[0]);	/* 08 */
   step(00_19, d, e, t, a, b, c, prep2.u32[1]);	/* 09 */
   step(00_19, c, d, e, t, a, b, prep2.u32[2]);	/* 10 */
   step(00_19, b, c, d, e, t, a, prep2.u32[3]);	/* 11 */
   prep(prep2, W1, W2, W3, W0, K20_39);		/* prepare for 20 through 23 */
   step(00_19, a, b, c, d, e, t, prep0.u32[0]);	/* 12 */
   step(00_19, t, a, b, c, d, e, prep0.u32[1]);	/* 13 */
   step(00_19, e, t, a, b, c, d, prep0.u32[2]);	/* 14 */
   step(00_19, d, e, t, a, b, c, prep0.u32[3]);	/* 15 */
   prep(prep0, W2, W3, W0, W1, K20_39);
   step(00_19, c, d, e, t, a, b, prep1.u32[0]);	/* 16 */
   step(00_19, b, c, d, e, t, a, prep1.u32[1]);	/* 17 */
   step(00_19, a, b, c, d, e, t, prep1.u32[2]);	/* 18 */
   step(00_19, t, a, b, c, d, e, prep1.u32[3]);	/* 19 */

   prep(prep1, W3, W0, W1, W2, K20_39);
   step(20_39, e, t, a, b, c, d, prep2.u32[0]);	/* 20 */
   step(20_39, d, e, t, a, b, c, prep2.u32[1]);	/* 21 */
   step(20_39, c, d, e, t, a, b, prep2.u32[2]);	/* 22 */
   step(20_39, b, c, d, e, t, a, prep2.u32[3]);	/* 23 */
   prep(prep2, W0, W1, W2, W3, K20_39);
   step(20_39, a, b, c, d, e, t, prep0.u32[0]);	/* 24 */
   step(20_39, t, a, b, c, d, e, prep0.u32[1]);	/* 25 */
   step(20_39, e, t, a, b, c, d, prep0.u32[2]);	/* 26 */
   step(20_39, d, e, t, a, b, c, prep0.u32[3]);	/* 27 */
   prep(prep0, W1, W2, W3, W0, K20_39);
   step(20_39, c, d, e, t, a, b, prep1.u32[0]);	/* 28 */
   step(20_39, b, c, d, e, t, a, prep1.u32[1]);	/* 29 */
   step(20_39, a, b, c, d, e, t, prep1.u32[2]);	/* 30 */
   step(20_39, t, a, b, c, d, e, prep1.u32[3]);	/* 31 */
   prep(prep1, W2, W3, W0, W1, K40_59);
   step(20_39, e, t, a, b, c, d, prep2.u32[0]);	/* 32 */
   step(20_39, d, e, t, a, b, c, prep2.u32[1]);	/* 33 */
   step(20_39, c, d, e, t, a, b, prep2.u32[2]);	/* 34 */
   step(20_39, b, c, d, e, t, a, prep2.u32[3]);	/* 35 */
   prep(prep2, W3, W0, W1, W2, K40_59);
   step(20_39, a, b, c, d, e, t, prep0.u32[0]);	/* 36 */
   step(20_39, t, a, b, c, d, e, prep0.u32[1]);	/* 37 */
   step(20_39, e, t, a, b, c, d, prep0.u32[2]);	/* 38 */
   step(20_39, d, e, t, a, b, c, prep0.u32[3]);	/* 39 */

   prep(prep0, W0, W1, W2, W3, K40_59);
   step(40_59, c, d, e, t, a, b, prep1.u32[0]);	/* 40 */
   step(40_59, b, c, d, e, t, a, prep1.u32[1]);	/* 41 */
   step(40_59, a, b, c, d, e, t, prep1.u32[2]);	/* 42 */
   step(40_59, t, a, b, c, d, e, prep1.u32[3]);	/* 43 */
   prep(prep1, W1, W2, W3, W0, K40_59);
   step(40_59, e, t, a, b, c, d, prep2.u32[0]);	/* 44 */
   step(40_59, d, e, t, a, b, c, prep2.u32[1]);	/* 45 */
   step(40_59, c, d, e, t, a, b, prep2.u32[2]);	/* 46 */
   step(40_59, b, c, d, e, t, a, prep2.u32[3]);	/* 47 */
   prep(prep2, W2, W3, W0, W1, K40_59);
   step(40_59, a, b, c, d, e, t, prep0.u32[0]);	/* 48 */
   step(40_59, t, a, b, c, d, e, prep0.u32[1]);	/* 49 */
   step(40_59, e, t, a, b, c, d, prep0.u32[2]);	/* 50 */
   step(40_59, d, e, t, a, b, c, prep0.u32[3]);	/* 51 */
   prep(prep0, W3, W0, W1, W2, K60_79);
   step(40_59, c, d, e, t, a, b, prep1.u32[0]);	/* 52 */
   step(40_59, b, c, d, e, t, a, prep1.u32[1]);	/* 53 */
   step(40_59, a, b, c, d, e, t, prep1.u32[2]);	/* 54 */
   step(40_59, t, a, b, c, d, e, prep1.u32[3]);	/* 55 */
   prep(prep1, W0, W1, W2, W3, K60_79);
   step(40_59, e, t, a, b, c, d, prep2.u32[0]);	/* 56 */
   step(40_59, d, e, t, a, b, c, prep2.u32[1]);	/* 57 */
   step(40_59, c, d, e, t, a, b, prep2.u32[2]);	/* 58 */
   step(40_59, b, c, d, e, t, a, prep2.u32[3]);	/* 59 */

   prep(prep2, W1, W2, W3, W0, K60_79);
   step(60_79, a, b, c, d, e, t, prep0.u32[0]);	/* 60 */
   step(60_79, t, a, b, c, d, e, prep0.u32[1]);	/* 61 */
   step(60_79, e, t, a, b, c, d, prep0.u32[2]);	/* 62 */
   step(60_79, d, e, t, a, b, c, prep0.u32[3]);	/* 63 */
   prep(prep0, W2, W3, W0, W1, K60_79);
   step(60_79, c, d, e, t, a, b, prep1.u32[0]);	/* 64 */
   step(60_79, b, c, d, e, t, a, prep1.u32[1]);	/* 65 */
   step(60_79, a, b, c, d, e, t, prep1.u32[2]);	/* 66 */
   step(60_79, t, a, b, c, d, e, prep1.u32[3]);	/* 67 */
   prep(prep1, W3, W0, W1, W2, K60_79);
   step(60_79, e, t, a, b, c, d, prep2.u32[0]);	/* 68 */
   step(60_79, d, e, t, a, b, c, prep2.u32[1]);	/* 69 */
   step(60_79, c, d, e, t, a, b, prep2.u32[2]);	/* 70 */
   step(60_79, b, c, d, e, t, a, prep2.u32[3]);	/* 71 */

   step(60_79, a, b, c, d, e, t, prep0.u32[0]);	/* 72 */
   step(60_79, t, a, b, c, d, e, prep0.u32[1]);	/* 73 */
   step(60_79, e, t, a, b, c, d, prep0.u32[2]);	/* 74 */
   step(60_79, d, e, t, a, b, c, prep0.u32[3]);	/* 75 */
   /* no more input to prepare */
   step(60_79, c, d, e, t, a, b, prep1.u32[0]);	/* 76 */
   step(60_79, b, c, d, e, t, a, prep1.u32[1]);	/* 77 */
   step(60_79, a, b, c, d, e, t, prep1.u32[2]);	/* 78 */
   step(60_79, t, a, b, c, d, e, prep1.u32[3]);	/* 79 */
   /* e, t, a, b, c, d */
   H[0] += e;
   H[1] += t;
   H[2] += a;
   H[3] += b;
   H[4] += c;
   }

}
