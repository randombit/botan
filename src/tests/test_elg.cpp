/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
  #include <botan/pubkey.h>
  #include "test_rng.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ELGAMAL)

class ElGamal_KAT_Tests : public Text_Based_Test
   {
   public:
      ElGamal_KAT_Tests() : Text_Based_Test(Test::data_file("pubkey/elgamal.vec"),
                                        {"P", "G", "X", "Msg", "Nonce", "Ciphertext"},
                                        {"Padding"},
                                        false)
         {}

      Test::Result run_one_test(const std::string&,
                                const std::map<std::string, std::string>& vars) override
         {
         const std::vector<uint8_t> plaintext  = get_req_bin(vars, "Msg");
         const std::vector<uint8_t> ciphertext = get_req_bin(vars, "Ciphertext");

         const BigInt p = get_req_bn(vars, "P");
         const BigInt g = get_req_bn(vars, "G");
         const BigInt x = get_req_bn(vars, "X");

         const std::string padding = get_opt_str(vars, "Padding", "Raw");
         Fixed_Output_RNG kat_rng(get_req_bin(vars, "Nonce"));

         Test::Result result("ElGamal");

         const Botan::DL_Group group(p, g);
         const Botan::ElGamal_PrivateKey privkey(Test::rng(), group, x);
         const Botan::ElGamal_PublicKey pubkey = privkey;

         Botan::PK_Encryptor_EME encryptor(pubkey, padding);
         Botan::PK_Decryptor_EME decryptor(privkey, padding);

         result.test_eq("encryption", encryptor.encrypt(plaintext, kat_rng), ciphertext);
         result.test_eq("decryption", decryptor.decrypt(ciphertext), plaintext);

         check_invalid_ciphertexts(result, decryptor, plaintext, ciphertext);

         return result;
         }
   };

BOTAN_REGISTER_TEST("elgamal_kat", ElGamal_KAT_Tests);

#endif

}

}

size_t test_elgamal()
   {
   using namespace Botan_Tests;

   return basic_error_report("elgamal_kat");
   }
