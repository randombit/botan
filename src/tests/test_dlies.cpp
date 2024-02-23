/*
* (C) 2014,2015 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include "test_pubkey.h"
   #include <botan/dh.h>
   #include <botan/dl_group.h>
   #include <botan/dlies.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DLIES) && defined(BOTAN_HAS_DIFFIE_HELLMAN)

class DLIES_KAT_Tests final : public Text_Based_Test {
   public:
      DLIES_KAT_Tests() : Text_Based_Test("pubkey/dlies.vec", "Kdf,Mac,MacKeyLen,Group,X1,X2,Msg,Ciphertext", "IV") {}

      Test::Result run_one_test(const std::string& cipher_algo, const VarMap& vars) override {
         const Botan::BigInt x1 = vars.get_req_bn("X1");
         const Botan::BigInt x2 = vars.get_req_bn("X2");

         const std::vector<uint8_t> input = vars.get_req_bin("Msg");
         const std::vector<uint8_t> expected = vars.get_req_bin("Ciphertext");

         const std::string kdf_algo = vars.get_req_str("Kdf");
         const std::string mac_algo = vars.get_req_str("Mac");
         const size_t mac_key_len = vars.get_req_sz("MacKeyLen");
         const std::string group_name = vars.get_req_str("Group");

         const auto iv = Botan::InitializationVector(vars.get_opt_bin("IV"));

         Test::Result result("DLIES " + cipher_algo);

         auto kdf = Botan::KDF::create(kdf_algo);
         if(!kdf) {
            result.test_note("Skipping due to missing KDF:  " + kdf_algo);
            return result;
         }

         auto mac = Botan::MAC::create(mac_algo);
         if(!mac) {
            result.test_note("Skipping due to missing MAC:  " + mac_algo);
            return result;
         }

         std::unique_ptr<Botan::Cipher_Mode> enc;
         std::unique_ptr<Botan::Cipher_Mode> dec;
         size_t cipher_key_len = 0;

         if(cipher_algo != "XOR") {
            enc = Botan::Cipher_Mode::create(cipher_algo, Botan::Cipher_Dir::Encryption);
            dec = Botan::Cipher_Mode::create(cipher_algo, Botan::Cipher_Dir::Decryption);

            if(!enc || !dec) {
               result.test_note("Skipping due to missing cipher:  " + mac_algo);
               return result;
            }

            cipher_key_len = enc->key_spec().maximum_keylength();
         }

         Botan::DL_Group domain(group_name);

         Botan::DH_PrivateKey from(domain, x1);
         Botan::DH_PrivateKey to(domain, x2);

         Botan::DLIES_Encryptor encryptor(
            from, this->rng(), kdf->new_object(), std::move(enc), cipher_key_len, mac->new_object(), mac_key_len);
         Botan::DLIES_Decryptor decryptor(
            to, this->rng(), std::move(kdf), std::move(dec), cipher_key_len, std::move(mac), mac_key_len);

         if(!iv.empty()) {
            encryptor.set_initialization_vector(iv);
            decryptor.set_initialization_vector(iv);
         }

         encryptor.set_other_key(to.public_value());

         result.test_eq("encryption", encryptor.encrypt(input, this->rng()), expected);
         result.test_eq("decryption", decryptor.decrypt(expected), input);

         check_invalid_ciphertexts(result, decryptor, input, expected, this->rng());

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "dlies", DLIES_KAT_Tests);

Test::Result test_xor() {
   Test::Result result("DLIES XOR");

   std::vector<std::string> kdfs = {"KDF2(SHA-512)", "KDF1-18033(SHA-512)"};
   std::vector<std::string> macs = {"HMAC(SHA-512)", "CMAC(AES-128)"};

   const size_t mac_key_len = 16;

   std::unique_ptr<Botan::KDF> kdf;
   std::unique_ptr<Botan::MAC> mac;

   auto rng = Test::new_rng("dlies_xor");

   Botan::DH_PrivateKey alice(*rng, Botan::DL_Group("modp/ietf/2048"));
   Botan::DH_PrivateKey bob(*rng, Botan::DL_Group("modp/ietf/2048"));

   for(const auto& kfunc : kdfs) {
      kdf = Botan::KDF::create(kfunc);

      if(!kdf) {
         result.test_note("Skipping due to missing KDF: " + kfunc);
         continue;
      }

      for(const auto& mfunc : macs) {
         mac = Botan::MAC::create(mfunc);

         if(!mac) {
            result.test_note("Skipping due to missing MAC: " + mfunc);
            continue;
         }

         Botan::DLIES_Encryptor encryptor(alice, *rng, kdf->new_object(), mac->new_object(), mac_key_len);

         // negative test: other pub key not set
         Botan::secure_vector<uint8_t> plaintext = rng->random_vec(32);

         result.test_throws("encrypt not possible without setting other public key",
                            [&encryptor, &plaintext, &rng]() { encryptor.encrypt(plaintext, *rng); });

         encryptor.set_other_key(bob.public_value());
         std::vector<uint8_t> ciphertext = encryptor.encrypt(plaintext, *rng);

         Botan::DLIES_Decryptor decryptor(bob, *rng, kdf->new_object(), mac->new_object(), mac_key_len);

         // negative test: ciphertext too short
         result.test_throws("ciphertext too short", [&decryptor]() { decryptor.decrypt(std::vector<uint8_t>(2)); });

         result.test_eq("decryption", decryptor.decrypt(ciphertext), plaintext);

         check_invalid_ciphertexts(result, decryptor, unlock(plaintext), ciphertext, *rng);
      }
   }

   return result;
}

class DLIES_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns = {test_xor};

         for(size_t i = 0; i != fns.size(); ++i) {
            try {
               results.push_back(fns[i]());
            } catch(std::exception& e) {
               results.push_back(Test::Result::Failure("DLIES unit tests " + std::to_string(i), e.what()));
            }
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "dlies_unit", DLIES_Unit_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
