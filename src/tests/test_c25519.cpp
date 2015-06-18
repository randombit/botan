/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_CURVE_25519)
#include <botan/curve25519.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>
#endif

using namespace Botan;

#if defined(BOTAN_HAS_CURVE_25519)

namespace {

size_t curve25519_scalar_kat(const std::string& secret_h,
                             const std::string& basepoint_h,
                             const std::string& out_h)
   {
   const std::vector<byte> secret = hex_decode(secret_h);
   const std::vector<byte> basepoint = hex_decode(basepoint_h);
   const std::vector<byte> out = hex_decode(out_h);

   std::vector<byte> got(32);
   curve25519_donna(&got[0], &secret[0], &basepoint[0]);

   if(got != out)
      {
      std::cout << "Got " << hex_encode(got) << " exp " << hex_encode(out) << "\n";
      return 1;
      }

   return 0;
   }

}
#endif

size_t test_curve25519()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_CURVE_25519)
   std::ifstream c25519_scalar(PK_TEST_DATA_DIR "/c25519_scalar.vec");

   fails += run_tests_bb(c25519_scalar, "Curve25519 ScalarMult", "Out", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return curve25519_scalar_kat(m["Secret"], m["Basepoint"], m["Out"]);
             });
#endif

   return fails;
   }

