/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BLOWFISH)

#include <botan/blowfish.h>

namespace Botan_Tests {

class Blowfish_Salted_Tests final : public Text_Based_Test
   {
   public:
      Blowfish_Salted_Tests() : Text_Based_Test("salted_blowfish.vec", "Key,Salt,Out") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("Blowfish salted key schedule");

         const std::vector<uint8_t> key      = vars.get_req_bin("Key");
         const std::vector<uint8_t> salt     = vars.get_req_bin("Salt");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         Botan::Blowfish blowfish;

         blowfish.salted_set_key(key.data(), key.size(),
                                 salt.data(), salt.size(), 0);

         std::vector<uint8_t> block(8);
         blowfish.encrypt(block);

         result.test_eq("Expected output", block, expected);

         return result;
         }
   };

BOTAN_REGISTER_TEST("block", "blowfish_salted", Blowfish_Salted_Tests);

}

#endif
