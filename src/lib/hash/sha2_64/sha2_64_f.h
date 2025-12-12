/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA2_64_F_H_
#define BOTAN_SHA2_64_F_H_

#include <botan/types.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/rotate.h>

namespace Botan {

/*
* SHA-512 F1 Function
*/
BOTAN_FORCE_INLINE void SHA2_64_F(uint64_t A,
                                  uint64_t B,
                                  uint64_t C,
                                  uint64_t& D,
                                  uint64_t E,
                                  uint64_t F,
                                  uint64_t G,
                                  uint64_t& H,
                                  uint64_t& M1,
                                  uint64_t M2,
                                  uint64_t M3,
                                  uint64_t M4,
                                  uint64_t magic) {
   H += magic + rho<14, 18, 41>(E) + choose(E, F, G) + M1;
   D += H;
   H += rho<28, 34, 39>(A) + majority(A, B, C);
   M1 += sigma<19, 61, 6>(M2) + M3 + sigma<1, 8, 7>(M4);
}

/*
* SHA-512 F1 Function (No Message Expansion)
*/
BOTAN_FORCE_INLINE void SHA2_64_F(
   uint64_t A, uint64_t B, uint64_t C, uint64_t& D, uint64_t E, uint64_t F, uint64_t G, uint64_t& H, uint64_t M) {
   H += rho<14, 18, 41>(E) + choose(E, F, G) + M;
   D += H;
   H += rho<28, 34, 39>(A) + majority(A, B, C);
}

}  // namespace Botan

#endif
