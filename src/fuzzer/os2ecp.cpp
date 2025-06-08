/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include <botan/ec_group.h>
#include <botan/ec_point.h>

namespace {

void check_os2ecp(const Botan::EC_Group& group, std::span<const uint8_t> in) {
   try {
      Botan::EC_AffinePoint(group, in);
   } catch(Botan::Exception& e) {}
}

}  // namespace

void fuzz(std::span<const uint8_t> in) {
   if(in.size() >= 256) {
      return;
   }

   static Botan::EC_Group p192 = Botan::EC_Group::from_name("secp192r1");
   static Botan::EC_Group p224 = Botan::EC_Group::from_name("secp224r1");
   static Botan::EC_Group p256 = Botan::EC_Group::from_name("secp256r1");
   static Botan::EC_Group p384 = Botan::EC_Group::from_name("secp384r1");
   static Botan::EC_Group p521 = Botan::EC_Group::from_name("secp521r1");
   static Botan::EC_Group bp256 = Botan::EC_Group::from_name("brainpool256r1");
   static Botan::EC_Group bp512 = Botan::EC_Group::from_name("brainpool512r1");

   check_os2ecp(p192, in);
   check_os2ecp(p224, in);
   check_os2ecp(p256, in);
   check_os2ecp(p384, in);
   check_os2ecp(p521, in);
   check_os2ecp(p521, in);
   check_os2ecp(bp256, in);
   check_os2ecp(bp512, in);
}
