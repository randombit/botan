/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_FPE_FE1)
   #include <botan/fpe_fe1.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_FPE_FE1)

class FPE_FE1_Tests final : public Text_Based_Test
   {
   public:
      FPE_FE1_Tests() : Text_Based_Test("fpe_fe1.vec", "Mod,In,Out,Key,Tweak") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt modulus  = vars.get_req_bn("Mod");
         const Botan::BigInt input    = vars.get_req_bn("In");
         const Botan::BigInt expected = vars.get_req_bn("Out");
         const std::vector<uint8_t> key      = vars.get_req_bin("Key");
         const std::vector<uint8_t> tweak    = vars.get_req_bin("Tweak");

         Test::Result result("FPE_FE1");

         const Botan::BigInt got = Botan::FPE::fe1_encrypt(modulus, input, key, tweak);

         result.test_eq("ciphertext", got, expected);

         const Botan::BigInt decry = Botan::FPE::fe1_decrypt(modulus, got, key, tweak);

         result.test_eq("decrypted", decry, input);

         return result;
         }

   };

BOTAN_REGISTER_TEST("misc", "fpe_fe1", FPE_FE1_Tests);

#endif

}
