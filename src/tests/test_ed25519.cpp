/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ED25519)
   #include "test_pubkey.h"
   #include <botan/data_src.h>
   #include <botan/ed25519.h>
   #include <botan/pkcs8.h>
   #include <botan/x509_key.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ED25519)

class Ed25519_Key_Validity_Tests : public PK_Key_Validity_Test {
   public:
      Ed25519_Key_Validity_Tests() : PK_Key_Validity_Test("Ed25519", "pubkey/ed25519_key_valid.vec", "Pubkey") {}

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> pubkey = vars.get_req_bin("Pubkey");
         return std::make_unique<Botan::Ed25519_PublicKey>(pubkey);
      }
};

class Ed25519_Verification_Tests : public PK_Signature_Verification_Test {
   public:
      Ed25519_Verification_Tests() :
            PK_Signature_Verification_Test("Ed25519", "pubkey/ed25519_verify.vec", "Pubkey,Msg,Signature", "Valid") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> pubkey = vars.get_req_bin("Pubkey");
         return std::make_unique<Botan::Ed25519_PublicKey>(pubkey);
      }
};

class Ed25519_Signature_Tests final : public PK_Signature_Generation_Test {
   public:
      Ed25519_Signature_Tests() :
            PK_Signature_Generation_Test("Ed25519", "pubkey/ed25519.vec", "Privkey,Pubkey,Msg,Signature") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const std::vector<uint8_t> privkey = vars.get_req_bin("Privkey");
         const std::vector<uint8_t> pubkey = vars.get_req_bin("Pubkey");

         Botan::secure_vector<uint8_t> seed(privkey.begin(), privkey.end());

         auto key = std::make_unique<Botan::Ed25519_PrivateKey>(seed);

         if(key->get_public_key() != pubkey) {
            throw Test_Error("Invalid Ed25519 key in test data");
         }

         return key;
      }
};

class Ed25519_Curdle_Format_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         // Keys from draft-ietf-curdle-pkix-04.txt
         const std::string priv_key_str =
            "-----BEGIN PRIVATE KEY-----\n"
            "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
            "-----END PRIVATE KEY-----\n";

         const std::string pub_key_str =
            "-----BEGIN PUBLIC KEY-----\n"
            "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
            "-----END PUBLIC KEY-----\n";

         Test::Result result("Ed25519 CURDLE format");

         Botan::DataSource_Memory priv_data(priv_key_str);
         auto priv_key = Botan::PKCS8::load_key(priv_data);
         result.confirm("Private key loaded", priv_key != nullptr);

         Botan::DataSource_Memory pub_data(pub_key_str);
         auto pub_key = Botan::X509::load_key(pub_data);
         result.confirm("Public key loaded", pub_key != nullptr);

         auto signer = priv_key->signer().with_rng(this->rng()).create();
         signer.update("message");
         std::vector<uint8_t> sig = signer.signature(this->rng());

         auto verifier = pub_key->signature_verifier().create();
         verifier.update("message");
         result.confirm("Signature valid", verifier.check_signature(sig));

         return std::vector<Test::Result>{result};
      }
};

class Ed25519_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {""}; }

      std::string algo_name() const override { return "Ed25519"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::Ed25519_PublicKey>(raw_pk);
      }
};

BOTAN_REGISTER_TEST("pubkey", "ed25519_key_valid", Ed25519_Key_Validity_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_verify", Ed25519_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_sign", Ed25519_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_curdle", Ed25519_Curdle_Format_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_keygen", Ed25519_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
