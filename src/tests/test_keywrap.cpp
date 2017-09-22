/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   #include <botan/rfc3394.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
class RFC3394_Keywrap_Tests final : public Text_Based_Test
   {
   public:
      RFC3394_Keywrap_Tests() : Text_Based_Test("rfc3394.vec", "Key,KEK,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("RFC3394 keywrap");

         try
            {
            const std::vector<uint8_t> expected = get_req_bin(vars, "Output");
            const std::vector<uint8_t> key = get_req_bin(vars, "Key");
            const std::vector<uint8_t> kek = get_req_bin(vars, "KEK");

            const Botan::SymmetricKey kek_sym(kek);
            const Botan::secure_vector<uint8_t> key_l(key.begin(), key.end());
            const Botan::secure_vector<uint8_t> exp_l(expected.begin(), expected.end());

            result.test_eq("encryption", Botan::rfc3394_keywrap(key_l, kek_sym), expected);
            result.test_eq("decryption", Botan::rfc3394_keyunwrap(exp_l, kek_sym), key);
            }
         catch(std::exception& e)
            {
            result.test_failure("", e.what());
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("rfc3394", RFC3394_Keywrap_Tests);
#endif

}

}
