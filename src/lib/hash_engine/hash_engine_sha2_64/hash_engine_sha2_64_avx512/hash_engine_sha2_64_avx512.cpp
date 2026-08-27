/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/simd_8x64.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_SIMD_8X64 BOTAN_FORCE_INLINE void rnd(const SIMD_8x64& A,
                                                   const SIMD_8x64& B,
                                                   const SIMD_8x64& C,
                                                   SIMD_8x64& D,
                                                   const SIMD_8x64& E,
                                                   const SIMD_8x64& F,
                                                   const SIMD_8x64& G,
                                                   SIMD_8x64& H,
                                                   const SIMD_8x64& W,
                                                   uint64_t K) {
   const auto T1 = H + E.sigma1() + SIMD_8x64::choose(E, F, G) + SIMD_8x64::splat(K) + W;
   const auto T2 = A.sigma0() + SIMD_8x64::majority(A, B, C);
   D += T1;
   H = T1 + T2;
}

template <size_t I>
BOTAN_FN_ISA_SIMD_8X64 BOTAN_FORCE_INLINE SIMD_8x64 next_w(SIMD_8x64 W[16]) {
   const auto& w15 = W[(I + 1) % 16];
   const auto& w2 = W[(I + 14) % 16];
   const auto s0 = w15.rotr<1>() ^ w15.rotr<8>() ^ w15.shr<7>();
   const auto s1 = w2.rotr<19>() ^ w2.rotr<61>() ^ w2.shr<6>();
   W[I] += s0 + s1 + W[(I + 9) % 16];
   return W[I];
}

}  // namespace

BOTAN_FN_ISA_SIMD_8X64 void sha2_64_mb_compress_x8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   SIMD_8x64 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_8x64::load_le(states + 64 * j);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // Initialized directly from the loads, since default construction
      // would zero the whole array first
      SIMD_8x64 W[16] = {SIMD_8x64::load_be<128>(blocks, 0, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 1, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 2, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 3, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 4, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 5, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 6, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 7, n, 0),
                         SIMD_8x64::load_be<128>(blocks, 0, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 1, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 2, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 3, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 4, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 5, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 6, n, 64),
                         SIMD_8x64::load_be<128>(blocks, 7, n, 64)};
      SIMD_8x64::transpose(W[0], W[1], W[2], W[3], W[4], W[5], W[6], W[7]);
      SIMD_8x64::transpose(W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15]);

      SIMD_8x64 A = S[0];
      SIMD_8x64 B = S[1];
      SIMD_8x64 C = S[2];
      SIMD_8x64 D = S[3];
      SIMD_8x64 E = S[4];
      SIMD_8x64 F = S[5];
      SIMD_8x64 G = S[6];
      SIMD_8x64 H = S[7];

      // Every index into W is a constant so that it can stay in registers
      rnd(A, B, C, D, E, F, G, H, W[0], SHA512_K[0]);
      rnd(H, A, B, C, D, E, F, G, W[1], SHA512_K[1]);
      rnd(G, H, A, B, C, D, E, F, W[2], SHA512_K[2]);
      rnd(F, G, H, A, B, C, D, E, W[3], SHA512_K[3]);
      rnd(E, F, G, H, A, B, C, D, W[4], SHA512_K[4]);
      rnd(D, E, F, G, H, A, B, C, W[5], SHA512_K[5]);
      rnd(C, D, E, F, G, H, A, B, W[6], SHA512_K[6]);
      rnd(B, C, D, E, F, G, H, A, W[7], SHA512_K[7]);
      rnd(A, B, C, D, E, F, G, H, W[8], SHA512_K[8]);
      rnd(H, A, B, C, D, E, F, G, W[9], SHA512_K[9]);
      rnd(G, H, A, B, C, D, E, F, W[10], SHA512_K[10]);
      rnd(F, G, H, A, B, C, D, E, W[11], SHA512_K[11]);
      rnd(E, F, G, H, A, B, C, D, W[12], SHA512_K[12]);
      rnd(D, E, F, G, H, A, B, C, W[13], SHA512_K[13]);
      rnd(C, D, E, F, G, H, A, B, W[14], SHA512_K[14]);
      rnd(B, C, D, E, F, G, H, A, W[15], SHA512_K[15]);

      for(size_t t = 16; t != 80; t += 16) {
         rnd(A, B, C, D, E, F, G, H, next_w<0>(W), SHA512_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, next_w<1>(W), SHA512_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, next_w<2>(W), SHA512_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, next_w<3>(W), SHA512_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, next_w<4>(W), SHA512_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, next_w<5>(W), SHA512_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, next_w<6>(W), SHA512_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, next_w<7>(W), SHA512_K[t + 7]);
         rnd(A, B, C, D, E, F, G, H, next_w<8>(W), SHA512_K[t + 8]);
         rnd(H, A, B, C, D, E, F, G, next_w<9>(W), SHA512_K[t + 9]);
         rnd(G, H, A, B, C, D, E, F, next_w<10>(W), SHA512_K[t + 10]);
         rnd(F, G, H, A, B, C, D, E, next_w<11>(W), SHA512_K[t + 11]);
         rnd(E, F, G, H, A, B, C, D, next_w<12>(W), SHA512_K[t + 12]);
         rnd(D, E, F, G, H, A, B, C, next_w<13>(W), SHA512_K[t + 13]);
         rnd(C, D, E, F, G, H, A, B, next_w<14>(W), SHA512_K[t + 14]);
         rnd(B, C, D, E, F, G, H, A, next_w<15>(W), SHA512_K[t + 15]);
      }

      S[0] += A;
      S[1] += B;
      S[2] += C;
      S[3] += D;
      S[4] += E;
      S[5] += F;
      S[6] += G;
      S[7] += H;
   }

   for(size_t j = 0; j != 8; ++j) {
      S[j].store_le(states + 64 * j);
   }
}

BOTAN_FN_ISA_SIMD_8X64 void sha2_64_mb_extract_x8(const uint8_t* states, uint8_t* digests) {
   SIMD_8x64 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_8x64::load_le(states + 64 * j);
   }

   // Each S[j] holds word j of all 8 lanes; the transpose turns that
   // into the 8 words of each lane
   SIMD_8x64::transpose(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7]);

   for(size_t l = 0; l != 8; ++l) {
      S[l].store_be(digests + 64 * l);
   }
}

}  // namespace Botan
