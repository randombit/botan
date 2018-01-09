/*
*
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <fstream>

#if defined(BOTAN_HAS_ECC_GROUP_CUSTOM)
   #include <botan/ec_group_custom.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP_CUSTOM)

namespace Botan_Tests {

namespace {

class ECC_Custom_Pointmult_Tests final : public Text_Based_Test
   {
   public:
      ECC_Custom_Pointmult_Tests() : Text_Based_Test("pubkey/ecc_custom.vec", "m,X,Y") {}

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override
         {
         const Botan::BigInt m = get_req_bn(vars, "m");
         const Botan::BigInt X = get_req_bn(vars, "X");
         const Botan::BigInt Y = get_req_bn(vars, "Y");

         Botan::EC_Group group(Botan::OIDS::lookup(group_id));

         const Botan::PointGFp p = group.get_base_point() * m;

         Test::Result result("ECC Custom Scalarmult " + group_id);
         result.test_eq("affine X", p.get_affine_x(), X);
         result.test_eq("affine Y", p.get_affine_y(), Y);

         return result;
         }
   };
    
Test::Result test_register_custom_curves()
   {
   Test::Result result("register custom curves");
   std::string file = Test::data_dir() + "/pubkey/ecc_custom_params.txt";
   try
      {
      std::ifstream file_stream(file);
      Botan::EC_Group_Text curves(file_stream);
      curves.add_curves(Test::rng());
      result.test_success("test_register_custom_curves successful");
       }
   catch(std::exception& e)
      {
      result.test_failure("", e.what());
      }
   catch(...)
      {
      result.test_failure(" threw unknown exception");
      }
   return result;
   }
    
class ECC_Custom_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_register_custom_curves());
         std::vector<Test::Result> pointmul = ECC_Custom_Pointmult_Tests().run();
         results.insert(results.end(), pointmul.begin(), pointmul.end());

         return results;
         }
   };
    
   
BOTAN_REGISTER_TEST("ecc_custom", ECC_Custom_Tests);

}

}
#endif
