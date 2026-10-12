/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/simd_4x32.h>

namespace Botan {

namespace {

// Independent groups of 4 lanes interleaved to hide the round latency
constexpr size_t Groups = 2;

static_assert(4 * Groups == sha2_32_mb_power8_lanes);

template <int ST, int SIX>
BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_4x32 vshasigmaw(const SIMD_4x32& x) {
#if defined(__clang__)
   // Clang only defines __builtin_crypto_vshasigmaw if crypto is enabled for the whole TU
   return SIMD_4x32(__builtin_altivec_crypto_vshasigmaw(x.raw(), ST, SIX));
#else
   return SIMD_4x32(__builtin_crypto_vshasigmaw(x.raw(), ST, SIX));
#endif
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_4x32 big_sigma0(const SIMD_4x32& x) {
   return vshasigmaw<1, 0>(x);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_4x32 big_sigma1(const SIMD_4x32& x) {
   return vshasigmaw<1, 0xF>(x);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_4x32 small_sigma0(const SIMD_4x32& x) {
   return vshasigmaw<0, 0>(x);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_4x32 small_sigma1(const SIMD_4x32& x) {
   return vshasigmaw<0, 0xF>(x);
}

/*
* Round R (mod 8) of the compression; the variables rotate through S
* by renaming rather than by moves
*/
template <size_t R>
BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE void rnd(SIMD_4x32 (&S)[8][Groups], const SIMD_4x32 (&W)[Groups], uint32_t K) {
   const auto k = SIMD_4x32::splat(K);

   for(size_t g = 0; g != Groups; ++g) {
      const auto& A = S[(8 - R) % 8][g];
      const auto& B = S[(9 - R) % 8][g];
      const auto& C = S[(10 - R) % 8][g];
      auto& D = S[(11 - R) % 8][g];
      const auto& E = S[(12 - R) % 8][g];
      const auto& F = S[(13 - R) % 8][g];
      const auto& G = S[(14 - R) % 8][g];
      auto& H = S[(15 - R) % 8][g];

      // H + W + K does not depend on the previous round
      const auto T1 = (H + W[g] + k) + SIMD_4x32::choose(E, F, G) + big_sigma1(E);
      const auto T2 = big_sigma0(A) + SIMD_4x32::majority(A, B, C);
      D += T1;
      H = T1 + T2;
   }
}

}  // namespace

BOTAN_FN_ISA_SHA2 void sha2_32_mb_compress_power8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   SIMD_4x32 S[8][Groups];
   for(size_t j = 0; j != 8; ++j) {
      for(size_t g = 0; g != Groups; ++g) {
         S[j][g] = SIMD_4x32::load_le(states + 16 * (j * Groups + g));
      }
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // The full schedule is expanded first, leaving the registers to the rounds
      SIMD_4x32 W[64][Groups];

      for(size_t g = 0; g != Groups; ++g) {
         const uint8_t* const* lane = blocks + 4 * g;
         for(size_t q = 0; q != 4; ++q) {
            const size_t off = 64 * n + 16 * q;
            auto X0 = SIMD_4x32::load_be(lane[0] + off);
            auto X1 = SIMD_4x32::load_be(lane[1] + off);
            auto X2 = SIMD_4x32::load_be(lane[2] + off);
            auto X3 = SIMD_4x32::load_be(lane[3] + off);
            SIMD_4x32::transpose(X0, X1, X2, X3);
            W[4 * q + 0][g] = X0;
            W[4 * q + 1][g] = X1;
            W[4 * q + 2][g] = X2;
            W[4 * q + 3][g] = X3;
         }
      }

      for(size_t t = 16; t != 64; ++t) {
         for(size_t g = 0; g != Groups; ++g) {
            W[t][g] = small_sigma1(W[t - 2][g]) + W[t - 7][g] + small_sigma0(W[t - 15][g]) + W[t - 16][g];
         }
      }

      SIMD_4x32 V[8][Groups];
      for(size_t j = 0; j != 8; ++j) {
         for(size_t g = 0; g != Groups; ++g) {
            V[j][g] = S[j][g];
         }
      }

      for(size_t t = 0; t != 64; t += 8) {
         rnd<0>(V, W[t + 0], SHA256_K[t + 0]);
         rnd<1>(V, W[t + 1], SHA256_K[t + 1]);
         rnd<2>(V, W[t + 2], SHA256_K[t + 2]);
         rnd<3>(V, W[t + 3], SHA256_K[t + 3]);
         rnd<4>(V, W[t + 4], SHA256_K[t + 4]);
         rnd<5>(V, W[t + 5], SHA256_K[t + 5]);
         rnd<6>(V, W[t + 6], SHA256_K[t + 6]);
         rnd<7>(V, W[t + 7], SHA256_K[t + 7]);
      }

      for(size_t j = 0; j != 8; ++j) {
         for(size_t g = 0; g != Groups; ++g) {
            S[j][g] += V[j][g];
         }
      }
   }

   for(size_t j = 0; j != 8; ++j) {
      for(size_t g = 0; g != Groups; ++g) {
         S[j][g].store_le(states + 16 * (j * Groups + g));
      }
   }
}

BOTAN_FN_ISA_SHA2 void sha2_32_mb_extract_power8(const uint8_t* states, uint8_t* digests) {
   for(size_t g = 0; g != Groups; ++g) {
      SIMD_4x32 S[8];
      for(size_t j = 0; j != 8; ++j) {
         S[j] = SIMD_4x32::load_le(states + 16 * (j * Groups + g));
      }

      // Each S[j] holds word j of 4 lanes; the transposes turn that into
      // the 8 words of each lane
      SIMD_4x32::transpose(S[0], S[1], S[2], S[3]);
      SIMD_4x32::transpose(S[4], S[5], S[6], S[7]);

      for(size_t i = 0; i != 4; ++i) {
         uint8_t* digest = digests + 32 * (4 * g + i);
         S[i].store_be(digest);
         S[4 + i].store_be(digest + 16);
      }
   }
}

}  // namespace Botan
