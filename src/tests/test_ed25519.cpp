/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ED25519)
   #include "test_pubkey.h"
   #include <botan/bigint.h>
   #include <botan/data_src.h>
   #include <botan/ed25519.h>
   #include <botan/pk_options.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/x509_key.h>
   #include <botan/internal/ed25519_scalar.h>
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

         auto key = std::make_unique<Botan::Ed25519_PrivateKey>(Botan::Ed25519_PrivateKey::from_seed(privkey));

         if(key->raw_public_key_bits() != pubkey) {
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
         result.test_is_true("Private key loaded", priv_key != nullptr);

         Botan::DataSource_Memory pub_data(pub_key_str);
         auto pub_key = Botan::X509::load_key(pub_data);
         result.test_is_true("Public key loaded", pub_key != nullptr);

         Botan::PK_Signer signer(*priv_key, this->rng(), Botan::PK_Signature_Options());
         signer.update("message");
         std::vector<uint8_t> sig = signer.signature(this->rng());

         Botan::PK_Verifier verifier(*pub_key, Botan::PK_Signature_Options());
         verifier.update("message");
         result.test_is_true("Signature valid", verifier.check_signature(sig));

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

class Ed25519_Scalar_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Ed25519_Scalar");

         const Botan::BigInt order("0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");

         auto to_bigint = [](const Botan::Ed25519_Scalar& s) {
            const auto b = s.to_bytes();
            std::vector<uint8_t> be(b.rbegin(), b.rend());
            return Botan::BigInt::from_bytes(be);
         };

         for(size_t trial = 0; trial != 32; ++trial) {
            std::array<uint8_t, 64> wide{};
            this->rng().randomize(wide);

            const auto s = Botan::Ed25519_Scalar::from_wide_bytes(wide);

            std::vector<uint8_t> be(wide.rbegin(), wide.rend());
            const auto ref = Botan::BigInt::from_bytes(be) % order;
            result.test_bin_eq("wide reduction matches BigInt", to_bigint(s).serialize(), ref.serialize());

            std::array<uint8_t, 32> narrow{};
            this->rng().randomize(narrow);
            const auto t = Botan::Ed25519_Scalar::from_bytes(narrow);

            result.test_bin_eq(
               "sum matches BigInt", to_bigint(s + t).serialize(), ((to_bigint(s) + to_bigint(t)) % order).serialize());

            result.test_bin_eq("product matches BigInt",
                               to_bigint(s * t).serialize(),
                               ((to_bigint(s) * to_bigint(t)) % order).serialize());
         }

         auto le_bytes_of = [](const Botan::BigInt& v) {
            std::array<uint8_t, 32> b{};
            const auto be = v.serialize(32);
            for(size_t i = 0; i != 32; ++i) {
               b[i] = be[31 - i];
            }
            return b;
         };

         result.test_is_true("order - 1 is canonical",
                             Botan::Ed25519_Scalar::from_canonical_bytes(le_bytes_of(order - 1)).has_value());
         result.test_is_true("order is not canonical",
                             !Botan::Ed25519_Scalar::from_canonical_bytes(le_bytes_of(order)).has_value());
         result.test_is_true("order + 1 is not canonical",
                             !Botan::Ed25519_Scalar::from_canonical_bytes(le_bytes_of(order + 1)).has_value());

         std::array<uint8_t, 32> all_ones{};
         all_ones.fill(0xFF);
         result.test_is_true("2^256-1 is not canonical",
                             !Botan::Ed25519_Scalar::from_canonical_bytes(all_ones).has_value());

         const auto zero = Botan::Ed25519_Scalar::from_canonical_bytes(std::array<uint8_t, 32>{});
         result.test_is_true("zero is canonical", zero.has_value());
         result.test_bin_eq("zero round trips", zero->to_bytes(), std::array<uint8_t, 32>{});

         result.test_bin_eq(
            "negated one is order - 1", to_bigint(-Botan::Ed25519_Scalar::one()).serialize(), (order - 1).serialize());
         result.test_bin_eq(
            "negated zero is zero", (-Botan::Ed25519_Scalar::zero()).to_bytes(), std::array<uint8_t, 32>{});
         result.test_bin_eq("one plus negated one is zero",
                            (Botan::Ed25519_Scalar::one() + -Botan::Ed25519_Scalar::one()).to_bytes(),
                            std::array<uint8_t, 32>{});

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "ed25519_scalar", Ed25519_Scalar_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_key_valid", Ed25519_Key_Validity_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_verify", Ed25519_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_sign", Ed25519_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_curdle", Ed25519_Curdle_Format_Tests);
BOTAN_REGISTER_TEST("pubkey", "ed25519_keygen", Ed25519_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
