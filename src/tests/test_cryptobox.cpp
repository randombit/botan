/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CRYPTO_BOX)
   #include <botan/cryptobox.h>
   #include <botan/hex.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_CRYPTO_BOX)

class Cryptobox_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("cryptobox");

         for(size_t i = 0; i <= 128; i += 7)
            {
            const std::string password = Test::random_password();
            const std::vector<uint8_t> input = unlock(Test::rng().random_vec(i));

            const std::string ciphertext =
               Botan::CryptoBox::encrypt(input.data(), input.size(), password, Test::rng());

            try
               {
               const std::string decrypted = Botan::CryptoBox::decrypt(ciphertext, password);

               const uint8_t* pt_b = reinterpret_cast<const uint8_t*>(decrypted.data());
               std::vector<uint8_t> pt_vec(pt_b, pt_b + decrypted.size());
               result.test_eq("decrypt", pt_vec, input);
               }
            catch(std::exception& e)
               {
               result.test_failure("cryptobox decrypt", e.what());
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("cryptobox", Cryptobox_Tests);

#endif

}

}
