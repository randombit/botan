/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include "test_pubkey.h"
  #include <botan/dlies.h>
  #include <botan/dh.h>
  #include <botan/pubkey.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_DIFFIE_HELLMAN)

class DLIES_KAT_Tests : public Text_Based_Test
   {
   public:
      DLIES_KAT_Tests() : Text_Based_Test(
         "pubkey/dlies.vec",
         {"P", "G", "X1", "X2", "Msg", "Ciphertext"})
         {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt x1 = get_req_bn(vars, "X1");
         const Botan::BigInt x2 = get_req_bn(vars, "X2");

         const std::vector<uint8_t> input    = get_req_bin(vars, "Msg");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Ciphertext");

         Botan::DL_Group domain(p, g);

         Botan::DH_PrivateKey from(Test::rng(), domain, x1);
         Botan::DH_PrivateKey to(Test::rng(), domain, x2);

         const std::string kdf = "KDF2(SHA-1)";
         const std::string mac = "HMAC(SHA-1)";
         const size_t mac_key_len = 16;

         Test::Result result("DLIES");

         Botan::DLIES_Encryptor encryptor(from,
                                          Botan::KDF::create(kdf).release(),
                                          Botan::MessageAuthenticationCode::create(mac).release(),
                                          mac_key_len);

         Botan::DLIES_Decryptor decryptor(to,
                                          Botan::KDF::create(kdf).release(),
                                          Botan::MessageAuthenticationCode::create(mac).release(),
                                          mac_key_len);

         encryptor.set_other_key(to.public_value());

         result.test_eq("encryption", encryptor.encrypt(input, Test::rng()), expected);
         result.test_eq("decryption", decryptor.decrypt(expected), input);

         check_invalid_ciphertexts(result, decryptor, input, expected);

         return result;
         }
   };

BOTAN_REGISTER_TEST("dlies", DLIES_KAT_Tests);

#endif

}

}
