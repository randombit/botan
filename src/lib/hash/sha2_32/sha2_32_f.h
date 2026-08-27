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
* SHA-256 round constants
*/
alignas(64) inline constexpr uint32_t SHA256_K[64] = {
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

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
   H += magic + rho<6, 11, 25>(E) + choose(E, F, G) + M1;
   D += H;
   H += rho<2, 13, 22>(A) + majority(A, B, C);
   M1 += sigma<17, 19, 10>(M2) + M3 + sigma<7, 18, 3>(M4);
}

/*
* SHA-256 F1 Function (No Message Expansion)
*/
BOTAN_FORCE_INLINE void SHA2_32_F(
   uint32_t A, uint32_t B, uint32_t C, uint32_t& D, uint32_t E, uint32_t F, uint32_t G, uint32_t& H, uint32_t M) {
   H += rho<6, 11, 25>(E) + choose(E, F, G) + M;
   D += H;
   H += rho<2, 13, 22>(A) + majority(A, B, C);
}

}  // namespace Botan

#endif
