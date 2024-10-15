/*
* (C) 2014,2015 Jack Lloyd
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include "test_rng.h"

#if defined(BOTAN_HAS_ECDSA)
   #include "test_pubkey.h"
   #include <botan/ecdsa.h>
   #include <botan/hash.h>
   #include <botan/pk_algs.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_Verification_Tests final : public PK_Signature_Verification_Test {
   public:
      ECDSA_Verification_Tests() :
            PK_Signature_Verification_Test("ECDSA", "pubkey/ecdsa_verify.vec", "Group,Px,Py,Msg,Signature", "Valid") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");
         const BigInt px = vars.get_req_bn("Px");
         const BigInt py = vars.get_req_bn("Py");
         const auto group = Botan::EC_Group::from_name(group_id);

         const Botan::EC_Point public_point = group.point(px, py);

         return std::make_unique<Botan::ECDSA_PublicKey>(group, public_point);
      }

      std::string default_padding(const VarMap& /*unused*/) const override { return "Raw"; }
};

class ECDSA_Wycheproof_Verification_Tests final : public PK_Signature_Verification_Test {
   public:
      ECDSA_Wycheproof_Verification_Tests() :
            PK_Signature_Verification_Test(
               "ECDSA", "pubkey/ecdsa_wycheproof.vec", "Group,Px,Py,Hash,Msg,Signature,Valid") {}

      bool clear_between_callbacks() const override { return false; }

      Botan::Signature_Format sig_format() const override { return Botan::Signature_Format::DerSequence; }

      bool test_random_invalid_sigs() const override { return false; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");
         const BigInt px = vars.get_req_bn("Px");
         const BigInt py = vars.get_req_bn("Py");
         const auto group = Botan::EC_Group::from_name(group_id);

         const Botan::EC_Point public_point = group.point(px, py);

         return std::make_unique<Botan::ECDSA_PublicKey>(group, public_point);
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }
};

class ECDSA_Signature_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      ECDSA_Signature_KAT_Tests() :
            PK_Signature_Generation_Test("ECDSA",
   #if defined(BOTAN_HAS_RFC6979_GENERATOR)
                                         "pubkey/ecdsa_rfc6979.vec",
                                         "Group,X,Hash,Msg,Signature") {
      }
   #else
                                         "pubkey/ecdsa_prob.vec",
                                         "Group,X,Hash,Msg,Nonce,Signature") {
      }
   #endif

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");
         const BigInt x = vars.get_req_bn("X");
         const auto group = Botan::EC_Group::from_name(group_id);

         return std::make_unique<Botan::ECDSA_PrivateKey>(this->rng(), group, x);
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }

   #if !defined(BOTAN_HAS_RFC6979_GENERATOR)
      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         // probabilistic ecdsa signature generation extracts more random than just the nonce,
         // but the nonce is extracted first
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }
   #endif
};

class ECDSA_KAT_Verification_Tests final : public PK_Signature_Verification_Test {
   public:
      ECDSA_KAT_Verification_Tests() :
            PK_Signature_Verification_Test("ECDSA",
   #if !defined(BOTAN_HAS_RFC6979_GENERATOR)
                                           "pubkey/ecdsa_rfc6979.vec",
                                           "Group,X,Hash,Msg,Signature") {
      }
   #else
                                           "pubkey/ecdsa_prob.vec",
                                           "Group,X,Hash,Msg,Nonce,Signature") {
      }
   #endif

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");
         const BigInt x = vars.get_req_bn("X");
         const auto group = Botan::EC_Group::from_name(group_id);

         Botan::ECDSA_PrivateKey priv_key(this->rng(), group, x);

         return priv_key.public_key();
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }
};

class ECDSA_Sign_Verify_DER_Test final : public PK_Sign_Verify_DER_Test {
   public:
      ECDSA_Sign_Verify_DER_Test() : PK_Sign_Verify_DER_Test("ECDSA", "SHA-512") {}

      std::unique_ptr<Botan::Private_Key> key() override {
         return Botan::create_private_key("ECDSA", this->rng(), "secp256r1");
      }
};

class ECDSA_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         auto grp = Botan::EC_Group::known_named_groups();
         return std::vector<std::string>(grp.begin(), grp.end());
      }

      std::string algo_name() const override { return "ECDSA"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_point = group.OS2ECP(raw_pk);
         return std::make_unique<Botan::ECDSA_PublicKey>(group, public_point);
      }
};

class ECDSA_Keygen_Stability_Tests final : public PK_Key_Generation_Stability_Test {
   public:
      ECDSA_Keygen_Stability_Tests() : PK_Key_Generation_Stability_Test("ECDSA", "pubkey/ecdsa_keygen.vec") {}
};

   #if defined(BOTAN_HAS_EMSA_RAW)

class ECDSA_Key_Recovery_Tests final : public Text_Based_Test {
   public:
      ECDSA_Key_Recovery_Tests() :
            Text_Based_Test("pubkey/ecdsa_key_recovery.vec", "Group,Msg,R,S,V,PubkeyX,PubkeyY") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ECDSA key recovery");

         const std::string group_id = vars.get_req_str("Group");
         const auto group = Botan::EC_Group::from_name(group_id);

         const BigInt R = vars.get_req_bn("R");
         const BigInt S = vars.get_req_bn("S");
         const uint8_t V = vars.get_req_u8("V");
         const std::vector<uint8_t> msg = vars.get_req_bin("Msg");
         const BigInt pubkey_x = vars.get_req_bn("PubkeyX");
         const BigInt pubkey_y = vars.get_req_bn("PubkeyY");

         try {
            Botan::ECDSA_PublicKey pubkey(group, msg, R, S, V);
            result.test_eq("Pubkey X coordinate", pubkey.public_point().get_affine_x(), pubkey_x);
            result.test_eq("Pubkey Y coordinate", pubkey.public_point().get_affine_y(), pubkey_y);

            const uint8_t computed_V = pubkey.recovery_param(msg, R, S);
            result.test_eq("Recovery param is correct", static_cast<size_t>(computed_V), static_cast<size_t>(V));

            Botan::PK_Verifier verifier(pubkey, "Raw");

            auto sig = Botan::BigInt::encode_fixed_length_int_pair(R, S, group.get_order_bytes());

            result.confirm("Signature verifies", verifier.verify_message(msg, sig));
         } catch(Botan::Exception& e) {
            result.test_failure("Failed to recover ECDSA public key", e.what());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecdsa_key_recovery", ECDSA_Key_Recovery_Tests);

   #endif

class ECDSA_Invalid_Key_Tests final : public Text_Based_Test {
   public:
      ECDSA_Invalid_Key_Tests() : Text_Based_Test("pubkey/ecdsa_invalid.vec", "Group,InvalidKeyX,InvalidKeyY") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ECDSA invalid keys");

         const std::string group_id = vars.get_req_str("Group");
         const auto group = Botan::EC_Group::from_name(group_id);
         const Botan::BigInt x = vars.get_req_bn("InvalidKeyX");
         const Botan::BigInt y = vars.get_req_bn("InvalidKeyY");

         if(auto pt = Botan::EC_AffinePoint::from_bigint_xy(group, x, y)) {
            result.test_failure("Invalid public key was deserialized");
         } else {
            result.test_success("Invalid public key was rejected");
         }

         return result;
      }
};

class ECDSA_AllGroups_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         const std::vector<std::string> hash_fn = {
            "SHA-256", "SHA-384", "SHA-512", "SHAKE-128(208)", "SHAKE-128(520)", "SHAKE-128(1032)"};

         for(const std::string& group_name : Botan::EC_Group::known_named_groups()) {
            Test::Result result("ECDSA " + group_name);

            result.start_timer();

            const auto group = Botan::EC_Group::from_name(group_name);

            const Botan::ECDSA_PrivateKey priv(rng(), group);
            const auto pub = priv.public_key();

            for(const auto& hash : hash_fn) {
               if(!Botan::HashFunction::create(hash)) {
                  continue;
               }

               try {
                  auto signer = priv.signer().with_rng(rng()).with_hash(hash).create();
                  auto verifier = pub->signature_verifier().with_hash(hash).create();

                  for(size_t i = 0; i != 16; ++i) {
                     auto message = rng().random_vec(rng().next_byte());
                     auto sig = signer.sign_message(message, rng());
                     result.test_eq("Expected signature size", sig.size(), 2 * group.get_order_bytes());

                     result.confirm("Signature accepted", verifier.verify_message(message, sig));

                     const auto corrupted_message = mutate_vec(message, rng(), true);
                     result.confirm("Modified message rejected", !verifier.verify_message(corrupted_message, sig));

                     const auto corrupted_sig = mutate_vec(sig, rng(), true);
                     result.confirm("Modified signature rejected", !verifier.verify_message(message, corrupted_sig));
                  }
               } catch(std::exception& e) {
                  result.test_failure("Exception", e.what());
               }
            }

            result.end_timer();
            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecdsa_verify", ECDSA_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_verify_wycheproof", ECDSA_Wycheproof_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_sign", ECDSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_verify_kat", ECDSA_KAT_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_sign_verify_der", ECDSA_Sign_Verify_DER_Test);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_keygen", ECDSA_Keygen_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_keygen_stability", ECDSA_Keygen_Stability_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_invalid", ECDSA_Invalid_Key_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdsa_all_groups", ECDSA_AllGroups_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
