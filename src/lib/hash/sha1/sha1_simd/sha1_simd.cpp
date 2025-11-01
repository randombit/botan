/*
* SHA-1 using SIMD instructions
* Based on public domain code by Dean Gaudet
*    (http://arctic.org/~dean/crypto/sha1.html)
* (C) 2009-2011,2023,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha1_f.h>
#include <botan/internal/simd_4x32.h>

namespace Botan {

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
W0 = W[t]..W[t+3]
*/
BOTAN_FORCE_INLINE SIMD_4x32 sha1_simd_next_w(SIMD_4x32& XW0, SIMD_4x32 XW1, SIMD_4x32 XW2, SIMD_4x32 XW3) {
   SIMD_4x32 T0 = XW0;                  // W[t-16..t-13]
   T0 ^= SIMD_4x32::alignr8(XW1, XW0);  // W[t-14..t-11]
   T0 ^= XW2;                           // W[t-8..t-5]
   T0 ^= XW3.shift_elems_right<1>();    // W[t-3..t-1] || 0

   /* unrotated W[t]..W[t+2] in T0 ... still need W[t+3] */

   // Extract w[t+0] into T2
   auto T2 = T0.shift_elems_left<3>();

   // Main rotation
   T0 = T0.rotl<1>();

   // Rotation of W[t+3] has rot by 2 to account for us working on non-rotated words
   T2 = T2.rotl<2>();

   // Merge rol(W[t+0], 1) into W[t+3]
   T0 ^= T2;

   XW0 = T0;
   return T0;
}

}  // namespace

/*
* SHA-1 Compression Function using SIMD for message expansion
*/
//static
void BOTAN_FN_ISA_SIMD_4X32 SHA_1::simd_compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using namespace SHA1_F;

   const SIMD_4x32 K00_19 = SIMD_4x32::splat(K1);
   const SIMD_4x32 K20_39 = SIMD_4x32::splat(K2);
   const SIMD_4x32 K40_59 = SIMD_4x32::splat(K3);
   const SIMD_4x32 K60_79 = SIMD_4x32::splat(K4);

   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      uint32_t PT[4];

      const auto block = in.take(block_bytes);

      SIMD_4x32 W0 = SIMD_4x32::load_be(&block[0]);  // NOLINT(*-container-data-pointer)
      SIMD_4x32 W1 = SIMD_4x32::load_be(&block[16]);
      SIMD_4x32 W2 = SIMD_4x32::load_be(&block[32]);
      SIMD_4x32 W3 = SIMD_4x32::load_be(&block[48]);

      SIMD_4x32 P0 = W0 + K00_19;
      SIMD_4x32 P1 = W1 + K00_19;
      SIMD_4x32 P2 = W2 + K00_19;
      SIMD_4x32 P3 = W3 + K00_19;

      P0.store_le(PT);
      F1(A, B, C, D, E, PT[0]);
      F1(E, A, B, C, D, PT[1]);
      F1(D, E, A, B, C, PT[2]);
      F1(C, D, E, A, B, PT[3]);
      P0 = sha1_simd_next_w(W0, W1, W2, W3) + K00_19;

      P1.store_le(PT);
      F1(B, C, D, E, A, PT[0]);
      F1(A, B, C, D, E, PT[1]);
      F1(E, A, B, C, D, PT[2]);
      F1(D, E, A, B, C, PT[3]);
      P1 = sha1_simd_next_w(W1, W2, W3, W0) + K20_39;

      P2.store_le(PT);
      F1(C, D, E, A, B, PT[0]);
      F1(B, C, D, E, A, PT[1]);
      F1(A, B, C, D, E, PT[2]);
      F1(E, A, B, C, D, PT[3]);
      P2 = sha1_simd_next_w(W2, W3, W0, W1) + K20_39;

      P3.store_le(PT);
      F1(D, E, A, B, C, PT[0]);
      F1(C, D, E, A, B, PT[1]);
      F1(B, C, D, E, A, PT[2]);
      F1(A, B, C, D, E, PT[3]);
      P3 = sha1_simd_next_w(W3, W0, W1, W2) + K20_39;

      P0.store_le(PT);
      F1(E, A, B, C, D, PT[0]);
      F1(D, E, A, B, C, PT[1]);
      F1(C, D, E, A, B, PT[2]);
      F1(B, C, D, E, A, PT[3]);
      P0 = sha1_simd_next_w(W0, W1, W2, W3) + K20_39;

      P1.store_le(PT);
      F2(A, B, C, D, E, PT[0]);
      F2(E, A, B, C, D, PT[1]);
      F2(D, E, A, B, C, PT[2]);
      F2(C, D, E, A, B, PT[3]);
      P1 = sha1_simd_next_w(W1, W2, W3, W0) + K20_39;

      P2.store_le(PT);
      F2(B, C, D, E, A, PT[0]);
      F2(A, B, C, D, E, PT[1]);
      F2(E, A, B, C, D, PT[2]);
      F2(D, E, A, B, C, PT[3]);
      P2 = sha1_simd_next_w(W2, W3, W0, W1) + K40_59;

      P3.store_le(PT);
      F2(C, D, E, A, B, PT[0]);
      F2(B, C, D, E, A, PT[1]);
      F2(A, B, C, D, E, PT[2]);
      F2(E, A, B, C, D, PT[3]);
      P3 = sha1_simd_next_w(W3, W0, W1, W2) + K40_59;

      P0.store_le(PT);
      F2(D, E, A, B, C, PT[0]);
      F2(C, D, E, A, B, PT[1]);
      F2(B, C, D, E, A, PT[2]);
      F2(A, B, C, D, E, PT[3]);
      P0 = sha1_simd_next_w(W0, W1, W2, W3) + K40_59;

      P1.store_le(PT);
      F2(E, A, B, C, D, PT[0]);
      F2(D, E, A, B, C, PT[1]);
      F2(C, D, E, A, B, PT[2]);
      F2(B, C, D, E, A, PT[3]);
      P1 = sha1_simd_next_w(W1, W2, W3, W0) + K40_59;

      P2.store_le(PT);
      F3(A, B, C, D, E, PT[0]);
      F3(E, A, B, C, D, PT[1]);
      F3(D, E, A, B, C, PT[2]);
      F3(C, D, E, A, B, PT[3]);
      P2 = sha1_simd_next_w(W2, W3, W0, W1) + K40_59;

      P3.store_le(PT);
      F3(B, C, D, E, A, PT[0]);
      F3(A, B, C, D, E, PT[1]);
      F3(E, A, B, C, D, PT[2]);
      F3(D, E, A, B, C, PT[3]);
      P3 = sha1_simd_next_w(W3, W0, W1, W2) + K60_79;

      P0.store_le(PT);
      F3(C, D, E, A, B, PT[0]);
      F3(B, C, D, E, A, PT[1]);
      F3(A, B, C, D, E, PT[2]);
      F3(E, A, B, C, D, PT[3]);
      P0 = sha1_simd_next_w(W0, W1, W2, W3) + K60_79;

      P1.store_le(PT);
      F3(D, E, A, B, C, PT[0]);
      F3(C, D, E, A, B, PT[1]);
      F3(B, C, D, E, A, PT[2]);
      F3(A, B, C, D, E, PT[3]);
      P1 = sha1_simd_next_w(W1, W2, W3, W0) + K60_79;

      P2.store_le(PT);
      F3(E, A, B, C, D, PT[0]);
      F3(D, E, A, B, C, PT[1]);
      F3(C, D, E, A, B, PT[2]);
      F3(B, C, D, E, A, PT[3]);
      P2 = sha1_simd_next_w(W2, W3, W0, W1) + K60_79;

      P3.store_le(PT);
      F4(A, B, C, D, E, PT[0]);
      F4(E, A, B, C, D, PT[1]);
      F4(D, E, A, B, C, PT[2]);
      F4(C, D, E, A, B, PT[3]);
      P3 = sha1_simd_next_w(W3, W0, W1, W2) + K60_79;

      P0.store_le(PT);
      F4(B, C, D, E, A, PT[0]);
      F4(A, B, C, D, E, PT[1]);
      F4(E, A, B, C, D, PT[2]);
      F4(D, E, A, B, C, PT[3]);

      P1.store_le(PT);
      F4(C, D, E, A, B, PT[0]);
      F4(B, C, D, E, A, PT[1]);
      F4(A, B, C, D, E, PT[2]);
      F4(E, A, B, C, D, PT[3]);

      P2.store_le(PT);
      F4(D, E, A, B, C, PT[0]);
      F4(C, D, E, A, B, PT[1]);
      F4(B, C, D, E, A, PT[2]);
      F4(A, B, C, D, E, PT[3]);

      P3.store_le(PT);
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
