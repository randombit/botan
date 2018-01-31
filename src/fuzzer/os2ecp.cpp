/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"
#include <botan/ec_group.h>
#include <botan/point_gfp.h>

namespace {

void check_os2ecp(const Botan::EC_Group& group, const uint8_t in[], size_t len)
   {
   try
      {
      Botan::PointGFp point = group.OS2ECP(in, len);
      }
   catch(Botan::Exception& e) {}
   }

}

void fuzz(const uint8_t in[], size_t len)
   {
   if(len >= 256)
      return;

   static Botan::EC_Group p192("secp192r1");
   static Botan::EC_Group p224("secp224r1");
   static Botan::EC_Group p256("secp256r1");
   static Botan::EC_Group p384("secp384r1");
   static Botan::EC_Group p521("secp521r1");
   static Botan::EC_Group bp256("brainpool256r1");
   static Botan::EC_Group bp512("brainpool512r1");

   check_os2ecp(p192, in, len);
   check_os2ecp(p224, in, len);
   check_os2ecp(p256, in, len);
   check_os2ecp(p384, in, len);
   check_os2ecp(p521, in, len);
   check_os2ecp(p521, in, len);
   check_os2ecp(bp256, in, len);
   check_os2ecp(bp512, in, len);
   }
