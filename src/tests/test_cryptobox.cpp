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

            // First verify decryption works
            try
               {
               const Botan::secure_vector<uint8_t> decrypted =
                  Botan::CryptoBox::decrypt_bin(ciphertext, password);
               result.test_eq("decrypt", decrypted, input);
               }
            catch(std::exception& e)
               {
               result.test_failure("cryptobox decrypt", e.what());
               }

            // Now corrupt a bit and ensure it fails
            try
               {
               std::string corrupted = ciphertext;
               corrupted[corrupted.size()/2]++;
               const std::string decrypted = Botan::CryptoBox::decrypt(corrupted, password);
               result.test_failure("Decrypted corrupted cryptobox message");
               }
            catch(Botan::Decoding_Error)
               {
               result.test_success("Rejected corrupted cryptobox message");
               }
            catch(Botan::Invalid_Argument)
               {
               result.test_success("Rejected corrupted cryptobox message");
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("cryptobox", Cryptobox_Tests);

#endif

}

}
