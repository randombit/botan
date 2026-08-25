/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_64.h>

#include <botan/internal/isa_extn.h>
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
   alignas(64) constexpr uint64_t SHA512_K[80] = {
      0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC, 0x3956C25BF348B538,
      0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118, 0xD807AA98A3030242, 0x12835B0145706FBE,
      0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2, 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235,
      0xC19BF174CF692694, 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
      0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5, 0x983E5152EE66DFAB,
      0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4, 0xC6E00BF33DA88FC2, 0xD5A79147930AA725,
      0x06CA6351E003826F, 0x142929670A0E6E70, 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED,
      0x53380D139D95B3DF, 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
      0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30, 0xD192E819D6EF5218,
      0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8, 0x19A4C116B8D2D0C8, 0x1E376C085141AB53,
      0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8, 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373,
      0x682E6FF3D6B2B8A3, 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
      0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B, 0xCA273ECEEA26619C,
      0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178, 0x06F067AA72176FBA, 0x0A637DC5A2C898A6,
      0x113F9804BEF90DAE, 0x1B710B35131C471B, 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC,
      0x431D67C49C100D4C, 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817};

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
