/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ML_DSA)
   #include "test_pubkey.h"
   #include <botan/ml_dsa.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ML_DSA)

class ML_DSA_Verify_KAT_Tests final : public PK_Signature_Verification_Test {
   public:
      ML_DSA_Verify_KAT_Tests() :
            PK_Signature_Verification_Test("ML-DSA", "pubkey/ml_dsa_verify.vec", "Mode,Key,Msg,Signature,Valid") {}

      bool clear_between_callbacks() const override { return false; }

      std::string default_padding(const VarMap& /*unused*/) const override { return "Pure"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         Botan::ML_DSA_Mode mode(vars.get_req_str("Mode"));
         return std::make_unique<Botan::ML_DSA_PublicKey>(vars.get_req_bin("Key"), mode);
      }
};

BOTAN_REGISTER_TEST("pubkey", "ml_dsa_verify", ML_DSA_Verify_KAT_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
