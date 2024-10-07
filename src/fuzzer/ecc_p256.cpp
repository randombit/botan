/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include "ecc_helper.h"

void fuzz(std::span<const uint8_t> in) {
   if(in.size() > 2 * 256 / 8) {
      return;
   }
   static Botan::EC_Group p256("secp256r1");
   return check_ecc_math(p256, in);
}
