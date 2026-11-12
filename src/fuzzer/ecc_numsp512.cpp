/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include "ecc_helper.h"

void fuzz(std::span<const uint8_t> in) {
   if(in.size() > 2 * 512 / 8) {
      return;
   }
   static const auto numsp512 = Botan::EC_Group::from_name("numsp512d1");
   return check_ecc_math(numsp512, in);
}
