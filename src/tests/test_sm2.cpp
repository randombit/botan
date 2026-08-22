/*
* (C) 2017 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SM2)
   #include "test_pubkey.h"
   #include "test_rng.h"
   #include <botan/ec_group.h>
   #include <botan/hash.h>
   #include <botan/pubkey.h>
   #include <botan/sm2.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_SM2)

std::unique_ptr<Botan::Private_Key> load_sm2_private_key(const VarMap& vars) {
   // group params
   const BigInt p = vars.get_req_bn("P");
   const BigInt a = vars.get_req_bn("A");
   const BigInt b = vars.get_req_bn("B");
   const BigInt xG = vars.get_req_bn("xG");
   const BigInt yG = vars.get_req_bn("yG");
   const BigInt order = vars.get_req_bn("Order");
   const BigInt x = vars.get_req_bn("x");
   const Botan::OID oid = Botan::OID(vars.get_req_str("Oid"));

   const Botan::EC_Group domain(oid, p, a, b, xG, yG, order);

   Botan::Null_RNG null_rng;
   return std::make_unique<Botan::SM2_PrivateKey>(null_rng, domain, x);
}

class SM2_Signature_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      SM2_Signature_KAT_Tests() :
            PK_Signature_Generation_Test(
               "SM2", "pubkey/sm2_sig.vec", "P,A,B,xG,yG,Order,Oid,Ident,Msg,x,Nonce,Signature", "Hash") {}

      bool skip_this_test(const std::string& /*header*/, const VarMap& /*vars*/) override {
         return !Botan::EC_Group::supports_application_specific_group();
      }

      bool clear_between_callbacks() const override { return false; }

      std::string default_padding(const VarMap& vars) const override {
         return vars.get_req_str("Ident") + "," + vars.get_opt_str("Hash", "SM3");
      }

      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_sm2_private_key(vars);
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_sig", SM2_Signature_KAT_Tests);

class SM2_Encryption_KAT_Tests final : public PK_Encryption_Decryption_Test {
   public:
      SM2_Encryption_KAT_Tests() :
            PK_Encryption_Decryption_Test(
               "SM2", "pubkey/sm2_enc.vec", "P,A,B,xG,yG,Order,Oid,Msg,x,Nonce,Ciphertext", "Hash") {}

      bool skip_this_test(const std::string& /*header*/, const VarMap& /*vars*/) override {
         return !Botan::EC_Group::supports_application_specific_group();
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_opt_str("Hash", "SM3"); }

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         return load_sm2_private_key(vars);
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_enc", SM2_Encryption_KAT_Tests);

class SM2_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"secp256r1", "sm2p256v1"}; }

      std::string algo_name() const override { return "SM2"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_key = Botan::EC_AffinePoint(group, raw_pk);
         return std::make_unique<Botan::SM2_PublicKey>(group, public_key);
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_keygen", SM2_Keygen_Tests);

class SM2_Invalid_Ciphertexts : public Text_Based_Test {
   public:
      SM2_Invalid_Ciphertexts() : Text_Based_Test("pubkey/sm2_invalid.vec", "Key,Ctext") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("SM2 invalid ciphertext");

         const auto key = vars.get_req_bin("Key");
         const auto ctext = vars.get_req_bin("Ctext");

         const auto group = Botan::EC_Group::from_name("sm2p256v1");
         const auto pkey = Botan::SM2_PrivateKey(group, Botan::EC_Scalar::deserialize(group, key).value());

         Botan::PK_Decryptor_EME dec(pkey, rng(), "SM3");

         result.test_throws<Botan::Exception>("Decryption should fail for invalid ciphertext",
                                              [&] { dec.decrypt(ctext); });

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_invalid_ctext", SM2_Invalid_Ciphertexts);

class SM2_Default_Hash_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("SM2 signature default hash");

         if(!Botan::EC_Group::supports_named_group("sm2p256v1")) {
            result.test_note("Skipping - sm2p256v1 not available");
            return {result};
         }

         const Botan::SM2_PrivateKey key(this->rng(), Botan::EC_Group::from_name("sm2p256v1"));
         const std::vector<uint8_t> msg = {0x61, 0x62, 0x63};

         Botan::PK_Signer signer(key, this->rng(), Botan::PK_Signature_Options());
         const auto sig = signer.sign_message(msg, this->rng());
         result.test_str_eq("Signer reports SM3", signer.hash_function(), "SM3");

         Botan::PK_Verifier default_verifier(key, Botan::PK_Signature_Options());
         result.test_is_true("Verifies with default hash", default_verifier.verify_message(msg, sig));

         Botan::PK_Verifier sm3_verifier(key, Botan::PK_Signature_Options().with_hash("SM3"));
         result.test_is_true("Verifies with explicit SM3", sm3_verifier.verify_message(msg, sig));

         Botan::PK_Verifier legacy_verifier(key, "1234567812345678,SM3");
         result.test_is_true("Verifies with legacy default userid and SM3", legacy_verifier.verify_message(msg, sig));

         if(Botan::HashFunction::create("SHA-256")) {
            Botan::PK_Verifier sha256_verifier(key, Botan::PK_Signature_Options().with_hash("SHA-256"));
            result.test_is_false("Does not verify with SHA-256", sha256_verifier.verify_message(msg, sig));
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "sm2_default_hash", SM2_Default_Hash_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
