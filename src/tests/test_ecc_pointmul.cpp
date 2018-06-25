/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
   #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)
class ECC_Pointmult_Tests final : public Text_Based_Test
   {
   public:
      ECC_Pointmult_Tests() : Text_Based_Test("pubkey/ecc.vec", "m,X,Y") {}

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override
         {
         Test::Result result("ECC Scalarmult " + group_id);

         const Botan::BigInt m = vars.get_req_bn("m");
         const Botan::BigInt X = vars.get_req_bn("X");
         const Botan::BigInt Y = vars.get_req_bn("Y");

         Botan::EC_Group group(Botan::OIDS::lookup(group_id));

         const Botan::PointGFp& base_point = group.get_base_point();

         const Botan::PointGFp p1 = base_point * m;
         result.test_eq("p1 affine X", p1.get_affine_x(), X);
         result.test_eq("p1 affine Y", p1.get_affine_y(), Y);

         std::vector<Botan::BigInt> ws;
         const Botan::PointGFp p2 = group.blinded_base_point_multiply(m, Test::rng(), ws);
         result.test_eq("p2 affine X", p2.get_affine_x(), X);
         result.test_eq("p2 affine Y", p2.get_affine_y(), Y);

         const Botan::PointGFp p3 = group.blinded_var_point_multiply(base_point, m, Test::rng(), ws);
         result.test_eq("p3 affine X", p3.get_affine_x(), X);
         result.test_eq("p3 affine Y", p3.get_affine_y(), Y);

         return result;
         }
   };

BOTAN_REGISTER_TEST("ecc_pointmul", ECC_Pointmult_Tests);

#endif

}

}
