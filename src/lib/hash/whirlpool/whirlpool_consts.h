/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WHIRLPOOL_CONSTS_H_
#define BOTAN_WHIRLPOOL_CONSTS_H_

#include <botan/types.h>
#include <botan/internal/loadstor.h>
#include <array>

namespace Botan {

// Derive the 256-byte S-box from the Whirlpool E and R mini-boxes
consteval std::array<uint8_t, 256> whirlpool_sbox() noexcept {
   constexpr uint8_t Ebox[16] = {1, 11, 9, 12, 13, 6, 15, 3, 14, 8, 7, 4, 10, 2, 5, 0};
   constexpr uint8_t Rbox[16] = {7, 12, 11, 13, 14, 4, 9, 15, 6, 3, 8, 10, 2, 5, 1, 0};

   // Derive the inverse of the E table
   uint8_t Eibox[16] = {};
   for(size_t i = 0; i != 16; ++i) {
      Eibox[Ebox[i]] = static_cast<uint8_t>(i);
   }

   std::array<uint8_t, 256> S = {};
   for(size_t i = 0; i != 256; ++i) {
      const uint8_t L = Ebox[i >> 4];
      const uint8_t R = Eibox[i & 0x0F];
      const uint8_t T = Rbox[L ^ R];
      S[i] = static_cast<uint8_t>((Ebox[L ^ T] << 4) | Eibox[R ^ T]);
   }
   return S;
}

// Round constants are from the first 64 elements of the sbox
template <bool LittleEndian = false>
consteval std::array<uint64_t, 10> whirlpool_rc(const std::array<uint8_t, 256>& S) noexcept {
   std::array<uint64_t, 10> RC = {};
   for(size_t r = 0; r != 10; ++r) {
      if(LittleEndian) {
         RC[r] = load_le<uint64_t>(S.data(), r);
      } else {
         RC[r] = load_be<uint64_t>(S.data(), r);
      }
   }
   return RC;
}

}  // namespace Botan

#endif
