/*
* (C) 2014,2015,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ELGAMAL)
   #include "test_pubkey.h"
   #include <botan/dl_group.h>
   #include <botan/elgamal.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ELGAMAL)

class ElGamal_Encrypt_Tests final : public PK_Encryption_Decryption_Test {
   public:
      ElGamal_Encrypt_Tests() :
            PK_Encryption_Decryption_Test(
               "ElGamal", "pubkey/elgamal_encrypt.vec", "Group,Secret,Nonce,Msg,Ciphertext", "Padding") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const Botan::BigInt x = vars.get_req_bn("Secret");
         const auto group = Botan::DL_Group::from_name(vars.get_req_str("Group"));

         return std::make_unique<Botan::ElGamal_PrivateKey>(group, x);
      }
};

class ElGamal_Decrypt_Tests final : public PK_Decryption_Test {
   public:
      ElGamal_Decrypt_Tests() : PK_Decryption_Test("ElGamal", "pubkey/elgamal_decrypt.vec", "P,G,X,Msg,Ciphertext") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         const Botan::DL_Group group(p, g);

         return std::make_unique<Botan::ElGamal_PrivateKey>(group, x);
      }
};

class ElGamal_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"modp/ietf/1024"}; }

      std::string algo_name() const override { return "ElGamal"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::ElGamal_PublicKey>(Botan::DL_Group::from_name(keygen_params),
                                                           Botan::BigInt(raw_pk));
      }
};

   #if defined(BOTAN_HAS_EME_PKCS1)

class ElGamal_Repeated_Decryption_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("ElGamal repeated decryption");

         const auto group = Botan::DL_Group::from_name("modp/ietf/1024");
         const Botan::ElGamal_PrivateKey key(rng(), group);

         const Botan::PK_Encryptor_EME enc(key, rng(), "PKCS1v15");
         const Botan::PK_Decryptor_EME dec(key, rng(), "PKCS1v15");

         std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> msgs;
         for(size_t i = 0; i != 3; ++i) {
            auto ptext = rng().random_vec<std::vector<uint8_t>>(16);
            auto ctext = enc.encrypt(ptext, rng());
            msgs.emplace_back(std::move(ptext), std::move(ctext));
         }

         // Enough decryptions with one decryptor that the blinding is refreshed
         for(size_t i = 0; i != 150; ++i) {
            const auto& [ptext, ctext] = msgs[i % msgs.size()];
            result.test_bin_eq("decryption", dec.decrypt(ctext), ptext);
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "elgamal_repeated_decrypt", ElGamal_Repeated_Decryption_Tests);

   #endif

BOTAN_REGISTER_TEST("pubkey", "elgamal_encrypt", ElGamal_Encrypt_Tests);
BOTAN_REGISTER_TEST("pubkey", "elgamal_decrypt", ElGamal_Decrypt_Tests);
BOTAN_REGISTER_TEST("pubkey", "elgamal_keygen", ElGamal_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
