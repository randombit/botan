/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/simd_4x64.h>

namespace Botan {

namespace {

BOTAN_FN_ISA_SIMD_4X64 BOTAN_FORCE_INLINE void rnd(const SIMD_4x64& A,
                                                   const SIMD_4x64& B,
                                                   const SIMD_4x64& C,
                                                   SIMD_4x64& D,
                                                   const SIMD_4x64& E,
                                                   const SIMD_4x64& F,
                                                   const SIMD_4x64& G,
                                                   SIMD_4x64& H,
                                                   const SIMD_4x64& W,
                                                   uint64_t K) {
   const auto T1 = H + E.sigma1() + SIMD_4x64::choose(E, F, G) + SIMD_4x64::splat(K) + W;
   const auto T2 = A.sigma0() + SIMD_4x64::majority(A, B, C);
   D += T1;
   H = T1 + T2;
}

BOTAN_FN_ISA_SIMD_4X64 BOTAN_FORCE_INLINE SIMD_4x64 next_w(SIMD_4x64 W[16], size_t i) {
   const auto& w15 = W[(i + 1) % 16];
   const auto& w2 = W[(i + 14) % 16];
   const auto s0 = w15.rotr<1>() ^ w15.rotr<8>() ^ w15.shr<7>();
   const auto s1 = w2.rotr<19>() ^ w2.rotr<61>() ^ w2.shr<6>();
   W[i] += s0 + s1 + W[(i + 9) % 16];
   return W[i];
}

}  // namespace

BOTAN_FN_ISA_SIMD_4X64 void sha2_64_mb_compress_x4(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   SIMD_4x64 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_4x64::load_le(states + 32 * j);
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // Initialized directly from the loads, since default construction
      // would zero the whole array first
      SIMD_4x64 W[16] = {SIMD_4x64::load_be<128>(blocks, 0, n, 0),
                         SIMD_4x64::load_be<128>(blocks, 1, n, 0),
                         SIMD_4x64::load_be<128>(blocks, 2, n, 0),
                         SIMD_4x64::load_be<128>(blocks, 3, n, 0),
                         SIMD_4x64::load_be<128>(blocks, 0, n, 32),
                         SIMD_4x64::load_be<128>(blocks, 1, n, 32),
                         SIMD_4x64::load_be<128>(blocks, 2, n, 32),
                         SIMD_4x64::load_be<128>(blocks, 3, n, 32),
                         SIMD_4x64::load_be<128>(blocks, 0, n, 64),
                         SIMD_4x64::load_be<128>(blocks, 1, n, 64),
                         SIMD_4x64::load_be<128>(blocks, 2, n, 64),
                         SIMD_4x64::load_be<128>(blocks, 3, n, 64),
                         SIMD_4x64::load_be<128>(blocks, 0, n, 96),
                         SIMD_4x64::load_be<128>(blocks, 1, n, 96),
                         SIMD_4x64::load_be<128>(blocks, 2, n, 96),
                         SIMD_4x64::load_be<128>(blocks, 3, n, 96)};
      for(size_t j = 0; j != 4; ++j) {
         SIMD_4x64::transpose(W[4 * j + 0], W[4 * j + 1], W[4 * j + 2], W[4 * j + 3]);
      }

      SIMD_4x64 A = S[0];
      SIMD_4x64 B = S[1];
      SIMD_4x64 C = S[2];
      SIMD_4x64 D = S[3];
      SIMD_4x64 E = S[4];
      SIMD_4x64 F = S[5];
      SIMD_4x64 G = S[6];
      SIMD_4x64 H = S[7];

      for(size_t t = 0; t != 16; t += 8) {
         rnd(A, B, C, D, E, F, G, H, W[t + 0], SHA512_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, W[t + 1], SHA512_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, W[t + 2], SHA512_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, W[t + 3], SHA512_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, W[t + 4], SHA512_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, W[t + 5], SHA512_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, W[t + 6], SHA512_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, W[t + 7], SHA512_K[t + 7]);
      }

      for(size_t t = 16; t != 80; t += 8) {
         rnd(A, B, C, D, E, F, G, H, next_w(W, (t + 0) % 16), SHA512_K[t + 0]);
         rnd(H, A, B, C, D, E, F, G, next_w(W, (t + 1) % 16), SHA512_K[t + 1]);
         rnd(G, H, A, B, C, D, E, F, next_w(W, (t + 2) % 16), SHA512_K[t + 2]);
         rnd(F, G, H, A, B, C, D, E, next_w(W, (t + 3) % 16), SHA512_K[t + 3]);
         rnd(E, F, G, H, A, B, C, D, next_w(W, (t + 4) % 16), SHA512_K[t + 4]);
         rnd(D, E, F, G, H, A, B, C, next_w(W, (t + 5) % 16), SHA512_K[t + 5]);
         rnd(C, D, E, F, G, H, A, B, next_w(W, (t + 6) % 16), SHA512_K[t + 6]);
         rnd(B, C, D, E, F, G, H, A, next_w(W, (t + 7) % 16), SHA512_K[t + 7]);
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

BOTAN_FN_ISA_SIMD_4X64 void sha2_64_mb_extract_x4(const uint8_t* states, uint8_t* digests) {
   SIMD_4x64 S[8];
   for(size_t j = 0; j != 8; ++j) {
      S[j] = SIMD_4x64::load_le(states + 32 * j);
   }

   // Each S[j] holds word j of all 4 lanes. After the transposes S[k]
   // holds words 0..3 of lane k and S[4+k] its words 4..7
   SIMD_4x64::transpose(S[0], S[1], S[2], S[3]);
   SIMD_4x64::transpose(S[4], S[5], S[6], S[7]);

   for(size_t l = 0; l != 4; ++l) {
      S[l].store_be(digests + 64 * l);
      S[4 + l].store_be(digests + 64 * l + 32);
   }
}

}  // namespace Botan
