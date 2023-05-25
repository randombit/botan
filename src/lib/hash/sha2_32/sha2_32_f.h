/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA2_32_F_H_
#define BOTAN_SHA2_32_F_H_

#include <botan/types.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/rotate.h>

namespace Botan {

/*
* SHA-256 F1 Function
*/
BOTAN_FORCE_INLINE void SHA2_32_F(uint32_t A,
                                  uint32_t B,
                                  uint32_t C,
                                  uint32_t& D,
                                  uint32_t E,
                                  uint32_t F,
                                  uint32_t G,
                                  uint32_t& H,
                                  uint32_t& M1,
                                  uint32_t M2,
                                  uint32_t M3,
                                  uint32_t M4,
                                  uint32_t magic) {
   uint32_t A_rho = rho<2, 13, 22>(A);
   uint32_t E_rho = rho<6, 11, 25>(E);
   uint32_t M2_sigma = sigma<17, 19, 10>(M2);
   uint32_t M4_sigma = sigma<7, 18, 3>(M4);
   H += magic + E_rho + choose(E, F, G) + M1;
   D += H;
   H += A_rho + majority(A, B, C);
   M1 += M2_sigma + M3 + M4_sigma;
}

}  // namespace Botan

#endif
