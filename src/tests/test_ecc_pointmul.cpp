/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECC_GROUP)

#if defined(BOTAN_HAS_ECDSA)

#include "test_pubkey.h"

#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/oids.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t ecc_point_mul(const std::string& group_id,
                     const std::string& m_s,
                     const std::string& X_s,
                     const std::string& Y_s)
   {
   EC_Group group(OIDS::lookup(group_id));

   const BigInt m(m_s);
   const BigInt X(X_s);
   const BigInt Y(Y_s);

   PointGFp p = group.get_base_point() * m;

   size_t fails = 0;

   if(p.get_affine_x() != X)
      {
      std::cout << p.get_affine_x() << " != " << X << std::endl;
      ++fails;
      }

   if(p.get_affine_y() != Y)
      {
      std::cout << p.get_affine_y() << " != " << Y << std::endl;
      ++fails;
      }

   return fails;
   }

}

size_t test_ecc_pointmul()
   {
   size_t fails = 0;

   std::ifstream ecc_mul(PK_TEST_DATA_DIR "/ecc.vec");

   fails += run_tests_bb(ecc_mul, "ECC Point Mult", "Y", false,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return ecc_point_mul(m["Group"], m["m"], m["X"], m["Y"]);
             });

   return fails;
   }

#else

UNTESTED_WARNING(ecc_pointmul);

#endif // BOTAN_HAS_ECDSA

#else

SKIP_TEST(ecc_pointmul);

#endif // BOTAN_HAS_ECC_GROUP
