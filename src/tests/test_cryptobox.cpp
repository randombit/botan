/*
* (C) 2014,2015,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_rng.h"

#if defined(BOTAN_HAS_CRYPTO_BOX)
   #include <botan/cryptobox.h>
   #include <botan/pem.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_CRYPTO_BOX)

class Cryptobox_KAT final : public Text_Based_Test
   {
   public:
      Cryptobox_KAT() : Text_Based_Test("cryptobox.vec", "Input,Passphrase,Salt,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("Cryptobox");

         const std::string password = vars.get_req_str("Passphrase");
         const std::vector<uint8_t> input    = vars.get_req_bin("Input");
         const std::vector<uint8_t> salt     = vars.get_req_bin("Salt");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         const std::string expected_pem = Botan::PEM_Code::encode(expected, "BOTAN CRYPTOBOX MESSAGE");

         Fixed_Output_RNG salt_rng(salt);

         const std::string ciphertext =
            Botan::CryptoBox::encrypt(input.data(), input.size(), password, salt_rng);

         result.test_eq("encryption is expected value", ciphertext, expected_pem);

         result.test_eq("decryption works", Botan::CryptoBox::decrypt_bin(ciphertext, password), input);

         // Now corrupt a bit and ensure it fails
         try
            {
            const std::vector<uint8_t> corrupted = Test::mutate_vec(expected);
            const std::string corrupted_pem = Botan::PEM_Code::encode(corrupted, "BOTAN CRYPTOBOX MESSAGE");

            Botan::CryptoBox::decrypt(corrupted_pem, password);
            result.test_failure("Decrypted corrupted cryptobox message", corrupted);
            }
         catch(Botan::Decoding_Error&)
            {
            result.test_success("Rejected corrupted cryptobox message");
            }
         catch(Botan::Invalid_Argument&)
            {
            result.test_success("Rejected corrupted cryptobox message");
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("misc", "cryptobox", Cryptobox_KAT);

#endif

}

}
