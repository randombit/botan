/*
* (C) 2014,2015 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
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
         {"Kdf", "Mac", "MacKeyLen", "Cipher", "CipherKeyLen", "IV", "P", "G", "X1", "X2", "Msg", "Ciphertext"})
         {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt x1 = get_req_bn(vars, "X1");
         const Botan::BigInt x2 = get_req_bn(vars, "X2");

         const std::vector<uint8_t> input    = get_req_bin(vars, "Msg");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Ciphertext");

         const std::string kdf_algo = get_req_str(vars, "Kdf");
         const std::string mac_algo = get_req_str(vars, "Mac");
         const size_t mac_key_len = get_req_sz(vars, "MacKeyLen");

         const std::string cipher_algo = get_opt_str(vars, "Cipher", "");
         const size_t cipher_key_len = get_opt_sz(vars, "CipherKeyLen", 0);
         const std::vector<uint8_t> iv = get_opt_bin(vars, "IV");

         Test::Result result("DLIES");

         std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create(kdf_algo));
         if(!kdf)
            {
            result.test_note("Skipping due to missing KDF:  " + kdf_algo);
            return result;
            }

         std::unique_ptr<Botan::MAC> mac(Botan::MAC::create(mac_algo));
         if(!mac)
            {
            result.test_note("Skipping due to missing MAC:  " + mac_algo);
            return result;
            }

         std::unique_ptr<Botan::Cipher_Mode> enc;
         std::unique_ptr<Botan::Cipher_Mode> dec;

         if(! cipher_algo.empty())
            {
            enc.reset(Botan::get_cipher_mode(cipher_algo, Botan::ENCRYPTION));
            dec.reset(Botan::get_cipher_mode(cipher_algo, Botan::DECRYPTION));
            }

         Botan::DL_Group domain(p, g);

         Botan::DH_PrivateKey from(Test::rng(), domain, x1);
         Botan::DH_PrivateKey to(Test::rng(), domain, x2);

         Botan::DLIES_Encryptor encryptor(from, kdf->clone(), enc.release(), cipher_key_len, mac->clone(), mac_key_len);
         Botan::DLIES_Decryptor decryptor(to, kdf.release(), dec.release(), cipher_key_len, mac.release(), mac_key_len);

         if(!iv.empty())
            {
            encryptor.set_initialization_vector(iv);
            decryptor.set_initialization_vector(iv);
            }

         encryptor.set_other_key(to.public_value());

         result.test_eq("encryption", encryptor.encrypt(input, Test::rng()), expected);
         result.test_eq("decryption", decryptor.decrypt(expected), input);

         check_invalid_ciphertexts(result, decryptor, input, expected);

         return result;
         }
   };

BOTAN_REGISTER_TEST("dlies", DLIES_KAT_Tests);

Test::Result test_xor()
   {
   Test::Result result("DLIES XOR");

   std::vector<std::string> kdfs = { "KDF2(SHA-512)", "KDF1-18033(SHA-512)" };
   std::vector<std::string> macs = { "HMAC(SHA-512)", "CMAC(AES-128)" };

   const size_t mac_key_len = 16;

   std::unique_ptr<Botan::KDF> kdf;
   std::unique_ptr<Botan::MAC> mac;

   Botan::DH_PrivateKey alice(Test::rng(), Botan::DL_Group("modp/ietf/2048"));
   Botan::DH_PrivateKey bob(Test::rng(), Botan::DL_Group("modp/ietf/2048"));

   for(const auto& kfunc : kdfs)
      {
      kdf = Botan::KDF::create(kfunc);

      if(!kdf)
         {
         result.test_note("Skipping due to missing KDF: " + kfunc);
         continue;
         }

      for(const auto& mfunc : macs)
         {
         mac = Botan::MAC::create(mfunc);

         if(!mac)
            {
            result.test_note("Skipping due to missing MAC: " + mfunc);
            continue;
            }

         Botan::DLIES_Encryptor encryptor(alice, kdf->clone(), mac->clone(), mac_key_len);

         // negative test: other pub key not set
         Botan::secure_vector<byte> plaintext = Test::rng().random_vec(32);

         result.test_throws("encrypt not possible without setting other public key", [&encryptor, &plaintext]()
            {
            encryptor.encrypt(plaintext, Test::rng());
            });

         encryptor.set_other_key(bob.public_value());
         std::vector<byte> ciphertext = encryptor.encrypt(plaintext, Test::rng());

         Botan::DLIES_Decryptor decryptor(bob, kdf->clone(), mac->clone(), mac_key_len);

         // negative test: ciphertext too short
         result.test_throws("ciphertext too short", [ &decryptor ]()
            {
            decryptor.decrypt(std::vector<byte>(2));
            });

         result.test_eq("decryption", decryptor.decrypt(ciphertext), plaintext);

         check_invalid_ciphertexts(result, decryptor, unlock(plaintext), ciphertext);
         }
      }

   return result;
   }

class DLIES_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns =
            {
            test_xor
            };

         for(size_t i = 0; i != fns.size(); ++i)
            {
            try
               {
               results.push_back(fns[ i ]());
               }
            catch(std::exception& e)
               {
               results.push_back(Test::Result::Failure("DLIES unit tests " + std::to_string(i), e.what()));
               }
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("dlies-unit", DLIES_Unit_Tests);

#endif

}

}
