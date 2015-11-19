/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDSA)
  #include "test_pubkey.h"
  #include <botan/pubkey.h>
  #include <botan/ecdsa.h>
  #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)
class ECC_Pointmult_Tests : public Text_Based_Test
   {
   public:
      ECC_Pointmult_Tests() : Text_Based_Test(
         Test::data_file("pubkey/ecc.vec"),
         {"Group", "m", "X", "Y"})
         {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");

         const Botan::BigInt m = get_req_bn(vars, "m");
         const Botan::BigInt X = get_req_bn(vars, "X");
         const Botan::BigInt Y = get_req_bn(vars, "Y");

         Botan::EC_Group group(Botan::OIDS::lookup(group_id));

         const Botan::PointGFp p = group.get_base_point() * m;

         Test::Result result("ECC Scalarmult");
         result.test_eq("affine X", p.get_affine_x(), X);
         result.test_eq("affine Y", p.get_affine_y(), Y);

         return result;
         }
   };

BOTAN_REGISTER_TEST("ecc_pointmul", ECC_Pointmult_Tests);

#endif

}

}
