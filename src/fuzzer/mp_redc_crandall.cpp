/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "mp_fuzzers.h"

#include <botan/bigint.h>
#include <botan/internal/loadstor.h>

void fuzz(std::span<const uint8_t> in) {
   if(in.size() != 8 * sizeof(word)) {
      return;
   }

#if BOTAN_MP_WORD_BITS == 64
   // secp256k1 modulus
   const word C = 0x1000003d1;
#else
   // 128 bit prime with largest possible C
   const word C = 0xffffffe1;
#endif

   static const Botan::BigInt refp = Botan::BigInt::power_of_2(4 * BOTAN_MP_WORD_BITS) - C;
   static const Botan::BigInt refp2 = refp * refp;

   const auto refz = Botan::BigInt::from_bytes(in);

   if(refz >= refp2) {
      return;
   }

   const auto refc = refz % refp;

   std::array<word, 8> z = {};
   for(size_t i = 0; i != 8; ++i) {
      z[7 - i] = Botan::load_be<word>(in.subspan(sizeof(word) * i, sizeof(word)));
   }

   const auto rc = Botan::redc_crandall<word, 4, C>(z);

   compare_word_vec(rc.data(), 4, refc._data(), refc.sig_words(), "Crandall reduction");
}
