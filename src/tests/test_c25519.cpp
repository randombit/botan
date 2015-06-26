/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CURVE_25519)

#include "test_pubkey.h"

#include <botan/curve25519.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t curve25519_scalar_kat(const std::string& secret_h,
                             const std::string& basepoint_h,
                             const std::string& out_h)
   {
   const std::vector<byte> secret = hex_decode(secret_h);
   const std::vector<byte> basepoint = hex_decode(basepoint_h);
   const std::vector<byte> out = hex_decode(out_h);

   std::vector<byte> got(32);
   curve25519_donna(got.data(), secret.data(), basepoint.data());

   if(got != out)
      {
      std::cout << "Got " << hex_encode(got) << " exp " << hex_encode(out) << std::endl;
      return 1;
      }

   return 0;
   }

}

size_t test_curve25519()
   {
   size_t fails = 0;

   std::ifstream c25519_scalar(PK_TEST_DATA_DIR "/c25519_scalar.vec");

   fails += run_tests_bb(c25519_scalar, "Curve25519 ScalarMult", "Out", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return curve25519_scalar_kat(m["Secret"], m["Basepoint"], m["Out"]);
             });

   return fails;
   }

#else

SKIP_TEST(curve25519);

#endif // BOTAN_HAS_CURVE_25519
