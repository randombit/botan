/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/simd_8x32.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE void rnd(const SIMD_8x32& A,
                                              const SIMD_8x32& B,
                                              const SIMD_8x32& C,
                                              SIMD_8x32& D,
                                              const SIMD_8x32& E,
                                              const SIMD_8x32& F,
                                              const SIMD_8x32& G,
                                              SIMD_8x32& H,
                                              const SIMD_8x32& W,
                                              uint32_t K) {
   const auto T1 = H + E.sigma1() + SIMD_8x32::choose(E, F, G) + SIMD_8x32::splat(K) + W;
   const auto T2 = A.sigma0() + SIMD_8x32::majority(A, B, C);
   D += T1;
   H = T1 + T2;
}

BOTAN_FN_ISA_AVX2 BOTAN_FORCE_INLINE SIMD_8x32 next_w(SIMD_8x32 W[16], size_t i) {
   const auto& w15 = W[(i + 1) % 16];
   const auto& w2 = W[(i + 14) % 16];
   const auto s0 = w15.rotr<7>() ^ w15.rotr<18>() ^ w15.shr<3>();
   const auto s1 = w2.rotr<17>() ^ w2.rotr<19>() ^ w2.shr<10>();
   W[i] += s0 + s1 + W[(i + 9) % 16];
   return W[i];
}

}  // namespace

BOTAN_FN_ISA_AVX2 void sha2_32_mb_compress_x8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   SIMD_8x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_8x32::load_le(states + 32 * j);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // Initialized directly from the loads, since default construction
      // would zero the whole array first
      SIMD_8x32 W[16] = {SIMD_8x32::load_be<64>(blocks, 0, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 1, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 2, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 3, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 4, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 5, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 6, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 7, n, 0),
                         SIMD_8x32::load_be<64>(blocks, 0, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 1, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 2, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 3, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 4, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 5, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 6, n, 32),
                         SIMD_8x32::load_be<64>(blocks, 7, n, 32)};
      SIMD_8x32::transpose(W[0], W[1], W[2], W[3], W[4], W[5], W[6], W[7]);
      SIMD_8x32::transpose(W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15]);

      SIMD_8x32 A = S[0];
      SIMD_8x32 B = S[1];
      SIMD_8x32 C = S[2];
      SIMD_8x32 D = S[3];
      SIMD_8x32 E = S[4];
      SIMD_8x32 F = S[5];
      SIMD_8x32 G = S[6];
      SIMD_8x32 H = S[7];

      for(size_t t = 0; t != 16; t += 8) {
         rnd(A, B, C, D, E, F, G, H, W[t + 0], SHA256_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, W[t + 1], SHA256_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, W[t + 2], SHA256_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, W[t + 3], SHA256_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, W[t + 4], SHA256_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, W[t + 5], SHA256_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, W[t + 6], SHA256_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, W[t + 7], SHA256_K[t + 7]);
      }

      for(size_t t = 16; t != 64; t += 8) {
         rnd(A, B, C, D, E, F, G, H, next_w(W, (t + 0) % 16), SHA256_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, next_w(W, (t + 1) % 16), SHA256_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, next_w(W, (t + 2) % 16), SHA256_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, next_w(W, (t + 3) % 16), SHA256_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, next_w(W, (t + 4) % 16), SHA256_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, next_w(W, (t + 5) % 16), SHA256_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, next_w(W, (t + 6) % 16), SHA256_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, next_w(W, (t + 7) % 16), SHA256_K[t + 7]);
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
      S[j].store_le(states + 32 * j);
   }
}

BOTAN_FN_ISA_AVX2 void sha2_32_mb_extract_x8(const uint8_t* states, uint8_t* digests) {
   SIMD_8x32 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_8x32::load_le(states + 32 * j);
   }

   // Each S[j] holds word j of all 8 lanes; the transpose turns that
   // into the 8 words of each lane
   SIMD_8x32::transpose(S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7]);

   for(size_t l = 0; l != 8; ++l) {
      S[l].store_be(digests + 32 * l);
   }
}

}  // namespace Botan
