/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/workfactor.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
class PK_Workfactor_Tests final : public Text_Based_Test
   {
   public:
      PK_Workfactor_Tests() :
         Text_Based_Test("pubkey/workfactor.vec", "ParamSize,Workfactor") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override
         {
         const size_t param_size  = vars.get_req_sz("ParamSize");
         const size_t exp_output  = vars.get_req_sz("Workfactor");

         size_t output = 0;

         // TODO: test McEliece strength tests also

         if(type == "RSA_Strength")
            {
            output = Botan::if_work_factor(param_size);
            }
         else if(type == "DL_Exponent_Size")
            {
            output = Botan::dl_exponent_size(param_size) / 2;
            }

         Test::Result result(type + " work factor calculation");
         result.test_eq("Calculated workfactor for " + std::to_string(param_size),
                        output, exp_output);
         return result;
         }
   };

BOTAN_REGISTER_TEST("pubkey", "pk_workfactor", PK_Workfactor_Tests);
#endif

}
