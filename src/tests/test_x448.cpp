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

}  // namespace

BOTAN_REGISTER_TEST("x448", "x448_keygen", X448_Keygen_Tests);
BOTAN_REGISTER_TEST("x448", "x448_agree", X448_Agreement_Tests);

}  // namespace Botan_Tests
#endif  // BOTAN_HAS_X448
