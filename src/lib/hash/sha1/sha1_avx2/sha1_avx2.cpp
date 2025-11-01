/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha1.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha1_f.h>
#include <botan/internal/simd_avx2.h>
#include <immintrin.h>

namespace Botan {

namespace {

/*
* This is exactly the same approach as used in sha1_simd.cpp, just done
* twice in the two AVX2 "lanes" - remember that alignr and slli/srli
* here are working not across the entire register but instead as if
* there were two smaller vectors.
*/
BOTAN_FN_ISA_AVX2_BMI2 BOTAN_FORCE_INLINE SIMD_8x32 sha1_avx2_next_w(SIMD_8x32& XW0,
                                                                     SIMD_8x32 XW1,
                                                                     SIMD_8x32 XW2,
                                                                     SIMD_8x32 XW3) {
   SIMD_8x32 T0 = XW0;  // W[t-16..t-13]
   T0 ^= SIMD_8x32(_mm256_alignr_epi8(XW1.raw(), XW0.raw(), 8));
   T0 ^= XW2;                                         // W[t-8..t-5]
   T0 ^= SIMD_8x32(_mm256_srli_si256(XW3.raw(), 4));  // W[t-3..t-1] || 0

   /* unrotated W[t]..W[t+2] in T0 ... still need W[t+3] */

   // Extract w[t+0] into T2
   auto T2 = SIMD_8x32(_mm256_slli_si256(T0.raw(), 3 * 4));

   // Main rotation
   T0 = T0.rotl<1>();

   // Rotation of W[t+3] has rot by 2 to account for us working on non-rotated words
   T2 = T2.rotl<2>();

   // Merge rol(W[t+0], 1) into W[t+3]
   T0 ^= T2;

   XW0 = T0;
   return T0;
}

/*
* Helper for word permutation with zeroing because AVX2 is awful
*
* Clang and GCC both compile this to a couple of stored constants plus
* a vpermd/vpand pair.
*/
template <int I0, int I1, int I2, int I3, int I4, int I5, int I6, int I7>
BOTAN_FN_ISA_AVX2_BMI2 BOTAN_FORCE_INLINE SIMD_8x32 permute_words(SIMD_8x32 v) {
   const __m256i tbl = _mm256_setr_epi32(I0, I1, I2, I3, I4, I5, I6, I7);
   const __m256i mask = _mm256_setr_epi32(I0 >= 0 ? 0xFFFFFFFF : 0,
                                          I1 >= 0 ? 0xFFFFFFFF : 0,
                                          I2 >= 0 ? 0xFFFFFFFF : 0,
                                          I3 >= 0 ? 0xFFFFFFFF : 0,
                                          I4 >= 0 ? 0xFFFFFFFF : 0,
                                          I5 >= 0 ? 0xFFFFFFFF : 0,
                                          I6 >= 0 ? 0xFFFFFFFF : 0,
                                          I7 >= 0 ? 0xFFFFFFFF : 0);

   return SIMD_8x32(_mm256_and_si256(mask, _mm256_permutevar8x32_epi32(v.raw(), tbl)));
}

/*
This is the same approach as the (single buffer) SHA-1 expansion in sha1_simd.cpp
except unrolled further; instead of computing 4 words of W at once, we compute 8.

However this is complicated both by the SHA-1 recurrence and AVX2
limitations; it is faster than what's done in sha1_simd.cpp but only just barely.

The basic idea here is that when computing this (8x per message block):

W[j + 0] = rotl<1>(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]);
W[j + 1] = rotl<1>(W[j - 2] ^ W[j - 7] ^ W[j - 13] ^ W[j - 15]);
W[j + 2] = rotl<1>(W[j - 1] ^ W[j - 6] ^ W[j - 12] ^ W[j - 14]);
W[j + 3] = rotl<1>(W[j    ] ^ W[j - 5] ^ W[j - 11] ^ W[j - 13]);
W[j + 4] = rotl<1>(W[j + 1] ^ W[j - 4] ^ W[j - 10] ^ W[j - 12]);
W[j + 5] = rotl<1>(W[j + 2] ^ W[j - 3] ^ W[j -  9] ^ W[j - 11]);
W[j + 6] = rotl<1>(W[j + 3] ^ W[j - 2] ^ W[j -  8] ^ W[j - 10]);
W[j + 7] = rotl<1>(W[j + 4] ^ W[j - 1] ^ W[j -  7] ^ W[j -  9]);

We instead compute a partial expansion:

W[j + 0] = rotl<1>(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]);
W[j + 1] = rotl<1>(W[j - 2] ^ W[j - 7] ^ W[j - 13] ^ W[j - 15]);
W[j + 2] = rotl<1>(W[j - 1] ^ W[j - 6] ^ W[j - 12] ^ W[j - 14]);
W[j + 3] = rotl<1>(           W[j - 5] ^ W[j - 11] ^ W[j - 13]);
W[j + 4] = rotl<1>(           W[j - 4] ^ W[j - 10] ^ W[j - 12]);
W[j + 5] = rotl<1>(           W[j - 3] ^ W[j -  9] ^ W[j - 11]);
W[j + 6] = rotl<1>(           W[j - 2] ^ W[j -  8] ^ W[j - 10]);
W[j + 7] = rotl<1>(           W[j - 1] ^ W[j -  7] ^ W[j -  9]);

Then update it with values that were not available until the first expansion is
completed:

W[j + 3] ^= rotl<1>(W[j    ]);
W[j + 4] ^= rotl<1>(W[j + 1]);
W[j + 5] ^= rotl<1>(W[j + 2]);

And then update again with values not available until the second expansion step
is completed:

W[j + 6] ^= rotl<1>(W[j + 3]);
W[j + 7] ^= rotl<1>(W[j + 4]);
*/

BOTAN_FN_ISA_AVX2_BMI2 BOTAN_FORCE_INLINE SIMD_8x32 sha1_avx2_next_w2(SIMD_8x32& W0, SIMD_8x32 W2) {
   // W[j-16..j-9] ^ W[j-8...j-1]
   auto WN = W0 ^ W2;

   // XOR in W[j-3..j-1] || 0 || 0 || 0 || W[j-8...j-7]
   WN ^= permute_words<5, 6, 7, -1, -1, -1, 0, 1>(W2);

   // XOR in W[j-14...j-9] || 0 || 0
   WN ^= permute_words<2, 3, 4, 5, 6, 7, -1, -1>(W0);

   // Extract W[j...j+2], rotate, and XOR into W[j+3...j+5]
   auto T0 = permute_words<-1, -1, -1, 0, 1, 2, -1, -1>(WN).rotl<2>();
   WN = WN.rotl<1>();  // main block rotation

   WN ^= T0;

   // Extract W[j+3...j+4], rotate, and XOR into W[j+6...j+7]
   WN ^= permute_words<-1, -1, -1, -1, -1, -1, 3, 4>(WN).rotl<1>();

   W0 = WN;
   return WN;
}

}  // namespace

/*
* SHA-1 Compression Function using SIMD for message expansion
*/
//static
void BOTAN_FN_ISA_AVX2_BMI2 SHA_1::avx2_compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   using namespace SHA1_F;

   const SIMD_8x32 K11 = SIMD_8x32::splat(K1);
   const SIMD_8x32 K22 = SIMD_8x32::splat(K2);
   const SIMD_8x32 K33 = SIMD_8x32::splat(K3);
   const SIMD_8x32 K44 = SIMD_8x32::splat(K4);

   const SIMD_8x32 K12(K1, K1, K1, K1, K2, K2, K2, K2);
   const SIMD_8x32 K34(K3, K3, K3, K3, K4, K4, K4, K4);

   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];

   BufferSlicer in(input);

   while(blocks >= 2) {
      const auto block = in.take(2 * block_bytes);
      blocks -= 2;

      uint32_t W2[80] = {0};

      uint32_t PT[4];

      // NOLINTNEXTLINE(*-container-data-pointer)
      SIMD_8x32 XW0 = SIMD_8x32::load_be128(&block[0], &block[64]);
      SIMD_8x32 XW1 = SIMD_8x32::load_be128(&block[16], &block[80]);
      SIMD_8x32 XW2 = SIMD_8x32::load_be128(&block[32], &block[96]);
      SIMD_8x32 XW3 = SIMD_8x32::load_be128(&block[48], &block[112]);

      SIMD_8x32 P0 = XW0 + SIMD_8x32::splat(K1);
      SIMD_8x32 P1 = XW1 + SIMD_8x32::splat(K1);
      SIMD_8x32 P2 = XW2 + SIMD_8x32::splat(K1);
      SIMD_8x32 P3 = XW3 + SIMD_8x32::splat(K1);

      // NOLINTBEGIN(readability-suspicious-call-argument) XW rotation

      P0.store_le128(PT, &W2[0]);
      P0 = sha1_avx2_next_w(XW0, XW1, XW2, XW3) + SIMD_8x32::splat(K1);
      F1(A, B, C, D, E, PT[0]);
      F1(E, A, B, C, D, PT[1]);
      F1(D, E, A, B, C, PT[2]);
      F1(C, D, E, A, B, PT[3]);

      P1.store_le128(PT, &W2[4]);
      P1 = sha1_avx2_next_w(XW1, XW2, XW3, XW0) + SIMD_8x32::splat(K2);
      F1(B, C, D, E, A, PT[0]);
      F1(A, B, C, D, E, PT[1]);
      F1(E, A, B, C, D, PT[2]);
      F1(D, E, A, B, C, PT[3]);

      P2.store_le128(PT, &W2[8]);
      P2 = sha1_avx2_next_w(XW2, XW3, XW0, XW1) + SIMD_8x32::splat(K2);
      F1(C, D, E, A, B, PT[0]);
      F1(B, C, D, E, A, PT[1]);
      F1(A, B, C, D, E, PT[2]);
      F1(E, A, B, C, D, PT[3]);

      P3.store_le128(PT, &W2[12]);
      P3 = sha1_avx2_next_w(XW3, XW0, XW1, XW2) + SIMD_8x32::splat(K2);
      F1(D, E, A, B, C, PT[0]);
      F1(C, D, E, A, B, PT[1]);
      F1(B, C, D, E, A, PT[2]);
      F1(A, B, C, D, E, PT[3]);

      P0.store_le128(PT, &W2[16]);
      P0 = sha1_avx2_next_w(XW0, XW1, XW2, XW3) + SIMD_8x32::splat(K2);
      F1(E, A, B, C, D, PT[0]);
      F1(D, E, A, B, C, PT[1]);
      F1(C, D, E, A, B, PT[2]);
      F1(B, C, D, E, A, PT[3]);

      P1.store_le128(PT, &W2[20]);
      P1 = sha1_avx2_next_w(XW1, XW2, XW3, XW0) + SIMD_8x32::splat(K2);
      F2(A, B, C, D, E, PT[0]);
      F2(E, A, B, C, D, PT[1]);
      F2(D, E, A, B, C, PT[2]);
      F2(C, D, E, A, B, PT[3]);

      P2.store_le128(PT, &W2[24]);
      P2 = sha1_avx2_next_w(XW2, XW3, XW0, XW1) + SIMD_8x32::splat(K3);
      F2(B, C, D, E, A, PT[0]);
      F2(A, B, C, D, E, PT[1]);
      F2(E, A, B, C, D, PT[2]);
      F2(D, E, A, B, C, PT[3]);

      P3.store_le128(PT, &W2[28]);
      P3 = sha1_avx2_next_w(XW3, XW0, XW1, XW2) + SIMD_8x32::splat(K3);
      F2(C, D, E, A, B, PT[0]);
      F2(B, C, D, E, A, PT[1]);
      F2(A, B, C, D, E, PT[2]);
      F2(E, A, B, C, D, PT[3]);

      P0.store_le128(PT, &W2[32]);
      P0 = sha1_avx2_next_w(XW0, XW1, XW2, XW3) + SIMD_8x32::splat(K3);
      F2(D, E, A, B, C, PT[0]);
      F2(C, D, E, A, B, PT[1]);
      F2(B, C, D, E, A, PT[2]);
      F2(A, B, C, D, E, PT[3]);

      P1.store_le128(PT, &W2[36]);
      P1 = sha1_avx2_next_w(XW1, XW2, XW3, XW0) + SIMD_8x32::splat(K3);
      F2(E, A, B, C, D, PT[0]);
      F2(D, E, A, B, C, PT[1]);
      F2(C, D, E, A, B, PT[2]);
      F2(B, C, D, E, A, PT[3]);

      P2.store_le128(PT, &W2[40]);
      P2 = sha1_avx2_next_w(XW2, XW3, XW0, XW1) + SIMD_8x32::splat(K3);
      F3(A, B, C, D, E, PT[0]);
      F3(E, A, B, C, D, PT[1]);
      F3(D, E, A, B, C, PT[2]);
      F3(C, D, E, A, B, PT[3]);

      P3.store_le128(PT, &W2[44]);
      P3 = sha1_avx2_next_w(XW3, XW0, XW1, XW2) + SIMD_8x32::splat(K4);
      F3(B, C, D, E, A, PT[0]);
      F3(A, B, C, D, E, PT[1]);
      F3(E, A, B, C, D, PT[2]);
      F3(D, E, A, B, C, PT[3]);

      P0.store_le128(PT, &W2[48]);
      P0 = sha1_avx2_next_w(XW0, XW1, XW2, XW3) + SIMD_8x32::splat(K4);
      F3(C, D, E, A, B, PT[0]);
      F3(B, C, D, E, A, PT[1]);
      F3(A, B, C, D, E, PT[2]);
      F3(E, A, B, C, D, PT[3]);

      P1.store_le128(PT, &W2[52]);
      P1 = sha1_avx2_next_w(XW1, XW2, XW3, XW0) + SIMD_8x32::splat(K4);
      F3(D, E, A, B, C, PT[0]);
      F3(C, D, E, A, B, PT[1]);
      F3(B, C, D, E, A, PT[2]);
      F3(A, B, C, D, E, PT[3]);

      P2.store_le128(PT, &W2[56]);
      P2 = sha1_avx2_next_w(XW2, XW3, XW0, XW1) + SIMD_8x32::splat(K4);
      F3(E, A, B, C, D, PT[0]);
      F3(D, E, A, B, C, PT[1]);
      F3(C, D, E, A, B, PT[2]);
      F3(B, C, D, E, A, PT[3]);

      P3.store_le128(PT, &W2[60]);
      P3 = sha1_avx2_next_w(XW3, XW0, XW1, XW2) + SIMD_8x32::splat(K4);
      F4(A, B, C, D, E, PT[0]);
      F4(E, A, B, C, D, PT[1]);
      F4(D, E, A, B, C, PT[2]);
      F4(C, D, E, A, B, PT[3]);

      P0.store_le128(PT, &W2[64]);
      F4(B, C, D, E, A, PT[0]);
      F4(A, B, C, D, E, PT[1]);
      F4(E, A, B, C, D, PT[2]);
      F4(D, E, A, B, C, PT[3]);

      P1.store_le128(PT, &W2[68]);
      F4(C, D, E, A, B, PT[0]);
      F4(B, C, D, E, A, PT[1]);
      F4(A, B, C, D, E, PT[2]);
      F4(E, A, B, C, D, PT[3]);

      P2.store_le128(PT, &W2[72]);
      F4(D, E, A, B, C, PT[0]);
      F4(C, D, E, A, B, PT[1]);
      F4(B, C, D, E, A, PT[2]);
      F4(A, B, C, D, E, PT[3]);

      P3.store_le128(PT, &W2[76]);
      F4(E, A, B, C, D, PT[0]);
      F4(D, E, A, B, C, PT[1]);
      F4(C, D, E, A, B, PT[2]);
      F4(B, C, D, E, A, PT[3]);

      // NOLINTEND(readability-suspicious-call-argument)

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);

      // Second block with pre-expanded message
      F1(A, B, C, D, E, W2[0]);
      F1(E, A, B, C, D, W2[1]);
      F1(D, E, A, B, C, W2[2]);
      F1(C, D, E, A, B, W2[3]);
      F1(B, C, D, E, A, W2[4]);
      F1(A, B, C, D, E, W2[5]);
      F1(E, A, B, C, D, W2[6]);
      F1(D, E, A, B, C, W2[7]);
      F1(C, D, E, A, B, W2[8]);
      F1(B, C, D, E, A, W2[9]);
      F1(A, B, C, D, E, W2[10]);
      F1(E, A, B, C, D, W2[11]);
      F1(D, E, A, B, C, W2[12]);
      F1(C, D, E, A, B, W2[13]);
      F1(B, C, D, E, A, W2[14]);
      F1(A, B, C, D, E, W2[15]);
      F1(E, A, B, C, D, W2[16]);
      F1(D, E, A, B, C, W2[17]);
      F1(C, D, E, A, B, W2[18]);
      F1(B, C, D, E, A, W2[19]);
      F2(A, B, C, D, E, W2[20]);
      F2(E, A, B, C, D, W2[21]);
      F2(D, E, A, B, C, W2[22]);
      F2(C, D, E, A, B, W2[23]);
      F2(B, C, D, E, A, W2[24]);
      F2(A, B, C, D, E, W2[25]);
      F2(E, A, B, C, D, W2[26]);
      F2(D, E, A, B, C, W2[27]);
      F2(C, D, E, A, B, W2[28]);
      F2(B, C, D, E, A, W2[29]);
      F2(A, B, C, D, E, W2[30]);
      F2(E, A, B, C, D, W2[31]);
      F2(D, E, A, B, C, W2[32]);
      F2(C, D, E, A, B, W2[33]);
      F2(B, C, D, E, A, W2[34]);
      F2(A, B, C, D, E, W2[35]);
      F2(E, A, B, C, D, W2[36]);
      F2(D, E, A, B, C, W2[37]);
      F2(C, D, E, A, B, W2[38]);
      F2(B, C, D, E, A, W2[39]);
      F3(A, B, C, D, E, W2[40]);
      F3(E, A, B, C, D, W2[41]);
      F3(D, E, A, B, C, W2[42]);
      F3(C, D, E, A, B, W2[43]);
      F3(B, C, D, E, A, W2[44]);
      F3(A, B, C, D, E, W2[45]);
      F3(E, A, B, C, D, W2[46]);
      F3(D, E, A, B, C, W2[47]);
      F3(C, D, E, A, B, W2[48]);
      F3(B, C, D, E, A, W2[49]);
      F3(A, B, C, D, E, W2[50]);
      F3(E, A, B, C, D, W2[51]);
      F3(D, E, A, B, C, W2[52]);
      F3(C, D, E, A, B, W2[53]);
      F3(B, C, D, E, A, W2[54]);
      F3(A, B, C, D, E, W2[55]);
      F3(E, A, B, C, D, W2[56]);
      F3(D, E, A, B, C, W2[57]);
      F3(C, D, E, A, B, W2[58]);
      F3(B, C, D, E, A, W2[59]);
      F4(A, B, C, D, E, W2[60]);
      F4(E, A, B, C, D, W2[61]);
      F4(D, E, A, B, C, W2[62]);
      F4(C, D, E, A, B, W2[63]);
      F4(B, C, D, E, A, W2[64]);
      F4(A, B, C, D, E, W2[65]);
      F4(E, A, B, C, D, W2[66]);
      F4(D, E, A, B, C, W2[67]);
      F4(C, D, E, A, B, W2[68]);
      F4(B, C, D, E, A, W2[69]);
      F4(A, B, C, D, E, W2[70]);
      F4(E, A, B, C, D, W2[71]);
      F4(D, E, A, B, C, W2[72]);
      F4(C, D, E, A, B, W2[73]);
      F4(B, C, D, E, A, W2[74]);
      F4(A, B, C, D, E, W2[75]);
      F4(E, A, B, C, D, W2[76]);
      F4(D, E, A, B, C, W2[77]);
      F4(C, D, E, A, B, W2[78]);
      F4(B, C, D, E, A, W2[79]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint32_t PT[8];

      const auto block = in.take(block_bytes);

      SIMD_8x32 W0 = SIMD_8x32::load_be(&block[0]);  // NOLINT(*-container-data-pointer)
      SIMD_8x32 W2 = SIMD_8x32::load_be(&block[32]);

      SIMD_8x32 P0 = W0 + K11;
      SIMD_8x32 P2 = W2 + K11;

      P0.store_le(PT);
      P0 = sha1_avx2_next_w2(W0, W2) + K12;

      F1(A, B, C, D, E, PT[0]);
      F1(E, A, B, C, D, PT[1]);
      F1(D, E, A, B, C, PT[2]);
      F1(C, D, E, A, B, PT[3]);
      F1(B, C, D, E, A, PT[4]);
      F1(A, B, C, D, E, PT[5]);
      F1(E, A, B, C, D, PT[6]);
      F1(D, E, A, B, C, PT[7]);

      P2.store_le(PT);
      P2 = sha1_avx2_next_w2(W2, W0) + K22;

      F1(C, D, E, A, B, PT[0]);
      F1(B, C, D, E, A, PT[1]);
      F1(A, B, C, D, E, PT[2]);
      F1(E, A, B, C, D, PT[3]);
      F1(D, E, A, B, C, PT[4]);
      F1(C, D, E, A, B, PT[5]);
      F1(B, C, D, E, A, PT[6]);
      F1(A, B, C, D, E, PT[7]);

      P0.store_le(PT);
      P0 = sha1_avx2_next_w2(W0, W2) + K22;

      F1(E, A, B, C, D, PT[0]);
      F1(D, E, A, B, C, PT[1]);
      F1(C, D, E, A, B, PT[2]);
      F1(B, C, D, E, A, PT[3]);
      F2(A, B, C, D, E, PT[4]);
      F2(E, A, B, C, D, PT[5]);
      F2(D, E, A, B, C, PT[6]);
      F2(C, D, E, A, B, PT[7]);

      P2.store_le(PT);
      P2 = sha1_avx2_next_w2(W2, W0) + K33;

      F2(B, C, D, E, A, PT[0]);
      F2(A, B, C, D, E, PT[1]);
      F2(E, A, B, C, D, PT[2]);
      F2(D, E, A, B, C, PT[3]);
      F2(C, D, E, A, B, PT[4]);
      F2(B, C, D, E, A, PT[5]);
      F2(A, B, C, D, E, PT[6]);
      F2(E, A, B, C, D, PT[7]);

      P0.store_le(PT);
      P0 = sha1_avx2_next_w2(W0, W2) + K33;

      F2(D, E, A, B, C, PT[0]);
      F2(C, D, E, A, B, PT[1]);
      F2(B, C, D, E, A, PT[2]);
      F2(A, B, C, D, E, PT[3]);
      F2(E, A, B, C, D, PT[4]);
      F2(D, E, A, B, C, PT[5]);
      F2(C, D, E, A, B, PT[6]);
      F2(B, C, D, E, A, PT[7]);

      P2.store_le(PT);
      P2 = sha1_avx2_next_w2(W2, W0) + K34;

      F3(A, B, C, D, E, PT[0]);
      F3(E, A, B, C, D, PT[1]);
      F3(D, E, A, B, C, PT[2]);
      F3(C, D, E, A, B, PT[3]);
      F3(B, C, D, E, A, PT[4]);
      F3(A, B, C, D, E, PT[5]);
      F3(E, A, B, C, D, PT[6]);
      F3(D, E, A, B, C, PT[7]);

      P0.store_le(PT);
      P0 = sha1_avx2_next_w2(W0, W2) + K44;

      F3(C, D, E, A, B, PT[0]);
      F3(B, C, D, E, A, PT[1]);
      F3(A, B, C, D, E, PT[2]);
      F3(E, A, B, C, D, PT[3]);
      F3(D, E, A, B, C, PT[4]);
      F3(C, D, E, A, B, PT[5]);
      F3(B, C, D, E, A, PT[6]);
      F3(A, B, C, D, E, PT[7]);

      P2.store_le(PT);
      P2 = sha1_avx2_next_w2(W2, W0) + K44;

      F3(E, A, B, C, D, PT[0]);
      F3(D, E, A, B, C, PT[1]);
      F3(C, D, E, A, B, PT[2]);
      F3(B, C, D, E, A, PT[3]);
      F4(A, B, C, D, E, PT[4]);
      F4(E, A, B, C, D, PT[5]);
      F4(D, E, A, B, C, PT[6]);
      F4(C, D, E, A, B, PT[7]);

      P0.store_le(PT);

      F4(B, C, D, E, A, PT[0]);
      F4(A, B, C, D, E, PT[1]);
      F4(E, A, B, C, D, PT[2]);
      F4(D, E, A, B, C, PT[3]);
      F4(C, D, E, A, B, PT[4]);
      F4(B, C, D, E, A, PT[5]);
      F4(A, B, C, D, E, PT[6]);
      F4(E, A, B, C, D, PT[7]);

      P2.store_le(PT);

      F4(D, E, A, B, C, PT[0]);
      F4(C, D, E, A, B, PT[1]);
      F4(B, C, D, E, A, PT[2]);
      F4(A, B, C, D, E, PT[3]);
      F4(E, A, B, C, D, PT[4]);
      F4(D, E, A, B, C, PT[5]);
      F4(C, D, E, A, B, PT[6]);
      F4(B, C, D, E, A, PT[7]);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
   }
}

}  // namespace Botan
