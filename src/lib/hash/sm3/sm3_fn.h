/*
* (C) 2017 Ribose Inc.
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SM3_FN_H_
#define BOTAN_SM3_FN_H_

#include <botan/types.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/rotate.h>

namespace Botan {

inline uint32_t P0(uint32_t X) {
   return X ^ rotl<9>(X) ^ rotl<17>(X);
}

inline void R1(uint32_t A,
               uint32_t& B,
               uint32_t C,
               uint32_t& D,
               uint32_t E,
               uint32_t& F,
               uint32_t G,
               uint32_t& H,
               uint32_t TJ,
               uint32_t Wi,
               uint32_t Wj) {
   const uint32_t A12 = rotl<12>(A);
   const uint32_t SS1 = rotl<7>(A12 + E + TJ);
   const uint32_t TT1 = (A ^ B ^ C) + D + (SS1 ^ A12) + (Wi ^ Wj);
   const uint32_t TT2 = (E ^ F ^ G) + H + SS1 + Wi;

   B = rotl<9>(B);
   D = TT1;
   F = rotl<19>(F);
   H = P0(TT2);
}

inline void R2(uint32_t A,
               uint32_t& B,
               uint32_t C,
               uint32_t& D,
               uint32_t E,
               uint32_t& F,
               uint32_t G,
               uint32_t& H,
               uint32_t TJ,
               uint32_t Wi,
               uint32_t Wj) {
   const uint32_t A12 = rotl<12>(A);
   const uint32_t SS1 = rotl<7>(A12 + E + TJ);
   const uint32_t TT1 = majority(A, B, C) + D + (SS1 ^ A12) + (Wi ^ Wj);
   const uint32_t TT2 = choose(E, F, G) + H + SS1 + Wi;

   B = rotl<9>(B);
   D = TT1;
   F = rotl<19>(F);
   H = P0(TT2);
}

inline uint32_t P1(uint32_t X) {
   return X ^ rotl<15>(X) ^ rotl<23>(X);
}

inline uint32_t SM3_E(uint32_t W0, uint32_t W7, uint32_t W13, uint32_t W3, uint32_t W10) {
   return P1(W0 ^ W7 ^ rotl<15>(W13)) ^ rotl<7>(W3) ^ W10;
}

}  // namespace Botan

#endif
