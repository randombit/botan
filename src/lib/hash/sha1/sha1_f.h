/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA1_FN_H_
#define BOTAN_SHA1_FN_H_

#include <botan/types.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/rotate.h>

namespace Botan::SHA1_F {

constexpr uint32_t K1 = 0x5A827999;
constexpr uint32_t K2 = 0x6ED9EBA1;
constexpr uint32_t K3 = 0x8F1BBCDC;
constexpr uint32_t K4 = 0xCA62C1D6;

inline void F1(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t M) {
   E += choose(B, C, D) + M + rotl<5>(A);
   B = rotl<30>(B);
}

inline void F2(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t M) {
   E += (B ^ C ^ D) + M + rotl<5>(A);
   B = rotl<30>(B);
}

inline void F3(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t M) {
   E += majority(B, C, D) + M + rotl<5>(A);
   B = rotl<30>(B);
}

// NOTE: identical to F4 besides the constant addition
inline void F4(uint32_t A, uint32_t& B, uint32_t C, uint32_t D, uint32_t& E, uint32_t M) {
   E += (B ^ C ^ D) + M + rotl<5>(A);
   B = rotl<30>(B);
}

}  // namespace Botan::SHA1_F

#endif
