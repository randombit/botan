/*
* SHA-1 using SSE2
* Based on public domain code by Dean Gaudet
*    (http://arctic.org/~dean/crypto/sha1.html)
* (C) 2009-2011,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/rotate.h>
#include <botan/internal/simd_32.h>
#include <botan/internal/stl_util.h>
#include <emmintrin.h>

namespace Botan {

namespace SHA1_SSE2_F {

namespace {

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
BOTAN_FORCE_INLINE SIMD_4x32 prep(SIMD_4x32& XW0, SIMD_4x32 XW1, SIMD_4x32 XW2, SIMD_4x32 XW3, SIMD_4x32 K) {
   SIMD_4x32 T0 = XW0;
   /* load W[t-4] 16-byte aligned, and shift */
   SIMD_4x32 T2 = XW3.shift_elems_right<1>();
   /* get high 64-bits of XW0 into low 64-bits */
   SIMD_4x32 T1 = SIMD_4x32(_mm_shuffle_epi32(XW0.raw(), _MM_SHUFFLE(1, 0, 3, 2)));
   /* load high 64-bits of T1 */
   T1 = SIMD_4x32(_mm_unpacklo_epi64(T1.raw(), XW1.raw()));

   T0 ^= T1;
   T2 ^= XW2;
   T0 ^= T2;
   /* unrotated W[t]..W[t+2] in T0 ... still need W[t+3] */

   T2 = T0.shift_elems_left<3>();
   T0 = T0.rotl<1>();
   T2 = T2.rotl<2>();

   T0 ^= T2; /* T0 now has W[t+3] */

   XW0 = T0;
   return T0 + K;
}

/*
* SHA-1 F1 Function
*/
inline void F1(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += choose(B, C, D) + msg + rotl<5>(A);
   B = rotl<30>(B);
}

/*
* SHA-1 F2 Function
*/
inline void F2(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += (B ^ C ^ D) + msg + rotl<5>(A);
   B = rotl<30>(B);
}

/*
* SHA-1 F3 Function
*/
inline void F3(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += majority(B, C, D) + msg + rotl<5>(A);
   B = rotl<30>(B);
}

/*
* SHA-1 F4 Function
*/
inline void F4(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t msg) {
   E += (B ^ C ^ D) + msg + rotl<5>(A);
   B = rotl<30>(B);
}

}  // namespace

}  // namespace SHA1_SSE2_F

/*
* SHA-1 Compression Function using SSE for message expansion
*/
//static
BOTAN_FUNC_ISA("sse2") void SHA_1::sse2_compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using namespace SHA1_SSE2_F;

   const SIMD_4x32 K00_19 = SIMD_4x32::splat(0x5A827999);
   const SIMD_4x32 K20_39 = SIMD_4x32::splat(0x6ED9EBA1);
   const SIMD_4x32 K40_59 = SIMD_4x32::splat(0x8F1BBCDC);
   const SIMD_4x32 K60_79 = SIMD_4x32::splat(0xCA62C1D6);

   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4];

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      uint32_t PT[4];

      const auto block = in.take(block_bytes);

      SIMD_4x32 W0 = SIMD_4x32::load_be(&block[0]);
      SIMD_4x32 W1 = SIMD_4x32::load_be(&block[16]);
      SIMD_4x32 W2 = SIMD_4x32::load_be(&block[32]);
      SIMD_4x32 W3 = SIMD_4x32::load_be(&block[48]);

      SIMD_4x32 P0 = W0 + K00_19;
      SIMD_4x32 P1 = W1 + K00_19;
      SIMD_4x32 P2 = W2 + K00_19;
      SIMD_4x32 P3 = W3 + K00_19;

      SIMD_4x32(P0).store_le(PT);
      F1(A, B, C, D, E, PT[0]);
      F1(E, A, B, C, D, PT[1]);
      F1(D, E, A, B, C, PT[2]);
      F1(C, D, E, A, B, PT[3]);
      P0 = prep(W0, W1, W2, W3, K00_19);

      SIMD_4x32(P1).store_le(PT);
      F1(B, C, D, E, A, PT[0]);
      F1(A, B, C, D, E, PT[1]);
      F1(E, A, B, C, D, PT[2]);
      F1(D, E, A, B, C, PT[3]);
      P1 = prep(W1, W2, W3, W0, K20_39);

      SIMD_4x32(P2).store_le(PT);
      F1(C, D, E, A, B, PT[0]);
      F1(B, C, D, E, A, PT[1]);
      F1(A, B, C, D, E, PT[2]);
      F1(E, A, B, C, D, PT[3]);
      P2 = prep(W2, W3, W0, W1, K20_39);

      SIMD_4x32(P3).store_le(PT);
      F1(D, E, A, B, C, PT[0]);
      F1(C, D, E, A, B, PT[1]);
      F1(B, C, D, E, A, PT[2]);
      F1(A, B, C, D, E, PT[3]);
      P3 = prep(W3, W0, W1, W2, K20_39);

      SIMD_4x32(P0).store_le(PT);
      F1(E, A, B, C, D, PT[0]);
      F1(D, E, A, B, C, PT[1]);
      F1(C, D, E, A, B, PT[2]);
      F1(B, C, D, E, A, PT[3]);
      P0 = prep(W0, W1, W2, W3, K20_39);

      SIMD_4x32(P1).store_le(PT);
      F2(A, B, C, D, E, PT[0]);
      F2(E, A, B, C, D, PT[1]);
      F2(D, E, A, B, C, PT[2]);
      F2(C, D, E, A, B, PT[3]);
      P1 = prep(W1, W2, W3, W0, K20_39);

      SIMD_4x32(P2).store_le(PT);
      F2(B, C, D, E, A, PT[0]);
      F2(A, B, C, D, E, PT[1]);
      F2(E, A, B, C, D, PT[2]);
      F2(D, E, A, B, C, PT[3]);
      P2 = prep(W2, W3, W0, W1, K40_59);

      SIMD_4x32(P3).store_le(PT);
      F2(C, D, E, A, B, PT[0]);
      F2(B, C, D, E, A, PT[1]);
      F2(A, B, C, D, E, PT[2]);
      F2(E, A, B, C, D, PT[3]);
      P3 = prep(W3, W0, W1, W2, K40_59);

      SIMD_4x32(P0).store_le(PT);
      F2(D, E, A, B, C, PT[0]);
      F2(C, D, E, A, B, PT[1]);
      F2(B, C, D, E, A, PT[2]);
      F2(A, B, C, D, E, PT[3]);
      P0 = prep(W0, W1, W2, W3, K40_59);

      SIMD_4x32(P1).store_le(PT);
      F2(E, A, B, C, D, PT[0]);
      F2(D, E, A, B, C, PT[1]);
      F2(C, D, E, A, B, PT[2]);
      F2(B, C, D, E, A, PT[3]);
      P1 = prep(W1, W2, W3, W0, K40_59);

      SIMD_4x32(P2).store_le(PT);
      F3(A, B, C, D, E, PT[0]);
      F3(E, A, B, C, D, PT[1]);
      F3(D, E, A, B, C, PT[2]);
      F3(C, D, E, A, B, PT[3]);
      P2 = prep(W2, W3, W0, W1, K40_59);

      SIMD_4x32(P3).store_le(PT);
      F3(B, C, D, E, A, PT[0]);
      F3(A, B, C, D, E, PT[1]);
      F3(E, A, B, C, D, PT[2]);
      F3(D, E, A, B, C, PT[3]);
      P3 = prep(W3, W0, W1, W2, K60_79);

      SIMD_4x32(P0).store_le(PT);
      F3(C, D, E, A, B, PT[0]);
      F3(B, C, D, E, A, PT[1]);
      F3(A, B, C, D, E, PT[2]);
      F3(E, A, B, C, D, PT[3]);
      P0 = prep(W0, W1, W2, W3, K60_79);

      SIMD_4x32(P1).store_le(PT);
      F3(D, E, A, B, C, PT[0]);
      F3(C, D, E, A, B, PT[1]);
      F3(B, C, D, E, A, PT[2]);
      F3(A, B, C, D, E, PT[3]);
      P1 = prep(W1, W2, W3, W0, K60_79);

      SIMD_4x32(P2).store_le(PT);
      F3(E, A, B, C, D, PT[0]);
      F3(D, E, A, B, C, PT[1]);
      F3(C, D, E, A, B, PT[2]);
      F3(B, C, D, E, A, PT[3]);
      P2 = prep(W2, W3, W0, W1, K60_79);

      SIMD_4x32(P3).store_le(PT);
      F4(A, B, C, D, E, PT[0]);
      F4(E, A, B, C, D, PT[1]);
      F4(D, E, A, B, C, PT[2]);
      F4(C, D, E, A, B, PT[3]);
      P3 = prep(W3, W0, W1, W2, K60_79);

      SIMD_4x32(P0).store_le(PT);
      F4(B, C, D, E, A, PT[0]);
      F4(A, B, C, D, E, PT[1]);
      F4(E, A, B, C, D, PT[2]);
      F4(D, E, A, B, C, PT[3]);

      SIMD_4x32(P1).store_le(PT);
      F4(C, D, E, A, B, PT[0]);
      F4(B, C, D, E, A, PT[1]);
      F4(A, B, C, D, E, PT[2]);
      F4(E, A, B, C, D, PT[3]);

      SIMD_4x32(P2).store_le(PT);
      F4(D, E, A, B, C, PT[0]);
      F4(C, D, E, A, B, PT[1]);
      F4(B, C, D, E, A, PT[2]);
      F4(A, B, C, D, E, PT[3]);

      SIMD_4x32(P3).store_le(PT);
      F4(E, A, B, C, D, PT[0]);
      F4(D, E, A, B, C, PT[1]);
      F4(C, D, E, A, B, PT[2]);
      F4(B, C, D, E, A, PT[3]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
   }
}

}  // namespace Botan
