/*
 * X448 Tests
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#if defined(BOTAN_HAS_X448)

   #include "test_pubkey.h"
   #include <botan/hex.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/x448.h>

namespace Botan_Tests {

namespace {

class X448_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {""}; }

      std::string algo_name() const override { return "X448"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::X448_PublicKey>(raw_pk);
      }
};

class X448_Agreement_Tests final : public PK_Key_Agreement_Test {
   public:
      X448_Agreement_Tests() : PK_Key_Agreement_Test("X448", "pubkey/x448.vec", "Secret,CounterKey,K") {}

      bool agreement_should_fail(const std::string& /*unused*/, const VarMap& vars) const override {
         for(const auto byte : vars.get_req_bin("K")) {
            if(byte != 0) {
               return false;
            }
         }

         return true;
      }

      std::string default_kdf(const VarMap& /*unused*/) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& /*header*/, const VarMap& vars) override {
         const std::vector<uint8_t> secret_vec = vars.get_req_bin("Secret");
         const Botan::secure_vector<uint8_t> secret(secret_vec.begin(), secret_vec.end());
         return std::make_unique<Botan::X448_PrivateKey>(secret);
      }

      std::vector<uint8_t> load_their_key(const std::string& /*header*/, const VarMap& vars) override {
         return vars.get_req_bin("CounterKey");
      }
};

class X448_Key_Validity_Tests final : public PK_Key_Validity_Test {
   public:
      X448_Key_Validity_Tests() : PK_Key_Validity_Test("X448", "pubkey/x448_key_valid.vec", "PublicKey") {}

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> pk = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::X448_PublicKey>(pk);
      }
};

/**
* X448 key generation uses the Ed448 fixed-base multiplication; check that it
* matches the Montgomery ladder on the base point.
*/
class X448_Keygen_Consistency_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X448 keygen consistency");

         std::vector<uint8_t> basepoint(56);
         basepoint[0] = 5;

         const auto check = [&](std::span<const uint8_t> secret) {
            const Botan::X448_PrivateKey key(secret);
            const Botan::PK_Key_Agreement ka(key, this->rng(), "Raw");
            const auto via_ladder = ka.derive_key(56, basepoint).bits_of();
            result.test_bin_eq("public key matches ladder on base point", key.public_value(), via_ladder);
         };

         // Scalars at the clamping boundaries
         check(std::vector<uint8_t>(56, 0x00));
         check(std::vector<uint8_t>(56, 0xFF));
         check(std::vector<uint8_t>(56, 0x80));
         check(std::vector<uint8_t>(56, 0x03));

         for(size_t i = 0; i != 64; ++i) {
            check(this->rng().random_vec(56));
         }

         // 4*L is a valid clamped scalar and gives the identity, which encodes as u = 0
         const Botan::X448_PrivateKey four_l(Botan::hex_decode(
            "cc1361ad4a0ae38d543d1637ca09b38540da58bb266d3b11a78f28f3fdffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
         result.test_bin_eq("4*L gives u = 0", four_l.public_value(), std::vector<uint8_t>(56));

         return {result};
      }
};

}  // namespace

BOTAN_REGISTER_TEST("x448", "x448_keygen", X448_Keygen_Tests);
BOTAN_REGISTER_TEST("x448", "x448_agree", X448_Agreement_Tests);
BOTAN_REGISTER_TEST("x448", "x448_key_valid", X448_Key_Validity_Tests);
BOTAN_REGISTER_TEST("x448", "x448_keygen_consistency", X448_Keygen_Consistency_Test);

}  // namespace Botan_Tests
#endif  // BOTAN_HAS_X448
