/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include "ecc_helper.h"

void fuzz(const uint8_t in[], size_t len) {
   if(len > 2 * 384 / 8) {
      return;
   }
   static Botan::EC_Group p384("secp384r1");
   return check_ecc_math(p384, in, len);
}
