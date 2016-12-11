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

class Cryptobox_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         Test::Result result("cryptobox");

         const std::vector<uint8_t> msg = Botan::hex_decode("AABBCC");
         const std::string password = "secret";

         std::string ciphertext = Botan::CryptoBox::encrypt(msg.data(), msg.size(),
                                                            password,
                                                            Test::rng());

         try
            {
            std::string plaintext = Botan::CryptoBox::decrypt(ciphertext, password);

            const uint8_t* pt_b = reinterpret_cast<const uint8_t*>(plaintext.data());

            std::vector<uint8_t> pt_vec(pt_b, pt_b + plaintext.size());

            result.test_eq("decrypt", pt_vec, msg);
            }
         catch(std::exception& e)
            {
            result.test_failure("cryptobox decrypt", e.what());
            }

         results.push_back(result);
         return results;
         }
   };

BOTAN_REGISTER_TEST("cryptobox", Cryptobox_Tests);

#endif

}

}
