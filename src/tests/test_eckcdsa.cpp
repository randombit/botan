/*
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include "test_rng.h"

#if defined(BOTAN_HAS_ECKCDSA)
   #include "test_pubkey.h"
   #include <botan/eckcdsa.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECKCDSA)

class ECKCDSA_Signature_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      ECKCDSA_Signature_KAT_Tests() :
            PK_Signature_Generation_Test("ECKCDSA", "pubkey/eckcdsa.vec", "Group,X,Hash,Msg,Nonce,Signature") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         return !Botan::EC_Group::supports_named_group(vars.get_req_str("Group"));
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const std::string group_id = vars.get_req_str("Group");
         const BigInt x = vars.get_req_bn("X");
         const auto group = Botan::EC_Group::from_name(group_id);

         return std::make_unique<Botan::ECKCDSA_PrivateKey>(this->rng(), group, x);
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }

      std::unique_ptr<Botan::RandomNumberGenerator> test_rng(const std::vector<uint8_t>& nonce) const override {
         // eckcdsa signature generation extracts more random than just the nonce,
         // but the nonce is extracted first
         return std::make_unique<Fixed_Output_Position_RNG>(nonce, 1, this->rng());
      }
};

class ECKCDSA_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"secp256r1", "secp384r1", "secp521r1"}; }

      std::string algo_name() const override { return "ECKCDSA"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_key = Botan::EC_AffinePoint(group, raw_pk);
         return std::make_unique<Botan::ECKCDSA_PublicKey>(group, public_key);
      }
};

BOTAN_REGISTER_TEST("pubkey", "eckcdsa_sign", ECKCDSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "eckcdsa_keygen", ECKCDSA_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
