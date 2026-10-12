/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_64.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sha2_64_f.h>
#include <botan/internal/simd_2x64.h>

namespace Botan {

namespace {

// Independent groups of 2 lanes interleaved to hide the round latency
constexpr size_t Groups = 2;

static_assert(2 * Groups == sha2_64_mb_power8_lanes);

template <int ST, int SIX>
BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_2x64 vshasigmad(const SIMD_2x64& x) {
#if defined(__clang__)
   // Clang only defines __builtin_crypto_vshasigmad if crypto is enabled for the whole TU
   return SIMD_2x64(__builtin_altivec_crypto_vshasigmad(x.raw(), ST, SIX));
#else
   return SIMD_2x64(__builtin_crypto_vshasigmad(x.raw(), ST, SIX));
#endif
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_2x64 big_sigma0(const SIMD_2x64& x) {
   return vshasigmad<1, 0>(x);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_2x64 big_sigma1(const SIMD_2x64& x) {
   return vshasigmad<1, 0xF>(x);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_2x64 small_sigma0(const SIMD_2x64& x) {
   return vshasigmad<0, 0>(x);
}

BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE SIMD_2x64 small_sigma1(const SIMD_2x64& x) {
   return vshasigmad<0, 0xF>(x);
}

/*
* Round R (mod 8) of the compression; the variables rotate through S
* by renaming rather than by moves
*/
template <size_t R>
BOTAN_FN_ISA_SHA2 BOTAN_FORCE_INLINE void rnd(SIMD_2x64 (&S)[8][Groups], const SIMD_2x64 (&W)[Groups], uint64_t K) {
   const auto k = SIMD_2x64::splat(K);

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
      const auto T1 = (H + W[g] + k) + SIMD_2x64::choose(E, F, G) + big_sigma1(E);
      const auto T2 = big_sigma0(A) + SIMD_2x64::majority(A, B, C);
      D += T1;
      H = T1 + T2;
   }
}

}  // namespace

BOTAN_FN_ISA_SHA2 void sha2_64_mb_compress_power8(uint8_t* states, const uint8_t* const* blocks, size_t nblocks) {
   SIMD_2x64 S[8][Groups];
   for(size_t j = 0; j != 8; ++j) {
      for(size_t g = 0; g != Groups; ++g) {
         S[j][g] = SIMD_2x64::load_le(states + 16 * (j * Groups + g));
      }
   }

   for(size_t n = 0; n != nblocks; ++n) {
      // The full schedule is expanded first, leaving the registers to the rounds
      SIMD_2x64 W[80][Groups];

      for(size_t g = 0; g != Groups; ++g) {
         const uint8_t* const* lane = blocks + 2 * g;
         for(size_t q = 0; q != 8; ++q) {
            const size_t off = 128 * n + 16 * q;
            const auto X0 = SIMD_2x64::load_be(lane[0] + off);
            const auto X1 = SIMD_2x64::load_be(lane[1] + off);
            W[2 * q + 0][g] = SIMD_2x64::interleave_low(X0, X1);
            W[2 * q + 1][g] = SIMD_2x64::interleave_high(X0, X1);
         }
      }

      for(size_t t = 16; t != 80; ++t) {
         for(size_t g = 0; g != Groups; ++g) {
            W[t][g] = small_sigma1(W[t - 2][g]) + W[t - 7][g] + small_sigma0(W[t - 15][g]) + W[t - 16][g];
         }
      }

      SIMD_2x64 V[8][Groups];
      for(size_t j = 0; j != 8; ++j) {
         for(size_t g = 0; g != Groups; ++g) {
            V[j][g] = S[j][g];
         }
      }

      for(size_t t = 0; t != 80; t += 8) {
         rnd<0>(V, W[t + 0], SHA512_K[t + 0]);
         rnd<1>(V, W[t + 1], SHA512_K[t + 1]);
         rnd<2>(V, W[t + 2], SHA512_K[t + 2]);
         rnd<3>(V, W[t + 3], SHA512_K[t + 3]);
         rnd<4>(V, W[t + 4], SHA512_K[t + 4]);
         rnd<5>(V, W[t + 5], SHA512_K[t + 5]);
         rnd<6>(V, W[t + 6], SHA512_K[t + 6]);
         rnd<7>(V, W[t + 7], SHA512_K[t + 7]);
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

BOTAN_FN_ISA_SHA2 void sha2_64_mb_extract_power8(const uint8_t* states, uint8_t* digests) {
   for(size_t g = 0; g != Groups; ++g) {
      // Each state vector holds word j of 2 lanes
      for(size_t j = 0; j != 8; j += 2) {
         const auto S0 = SIMD_2x64::load_le(states + 16 * (j * Groups + g));
         const auto S1 = SIMD_2x64::load_le(states + 16 * ((j + 1) * Groups + g));
         SIMD_2x64::interleave_low(S0, S1).store_be(digests + 64 * (2 * g) + 8 * j);
         SIMD_2x64::interleave_high(S0, S1).store_be(digests + 64 * (2 * g + 1) + 8 * j);
      }
   }
}

}  // namespace Botan
