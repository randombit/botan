/*
* (C) 2024 Jack Lloyd
* (C) 2025 Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pubkey_pqc.h"
#include "tests.h"

#if defined(BOTAN_HAS_ML_DSA)
   #include "test_pubkey.h"
   #include <botan/ml_dsa.h>
   #include <botan/internal/stl_util.h>
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

class ML_DSA_ACVP_KAT_KeyGen_Tests final : public PK_PQC_ACVP_KAT_KeyGen_Test {
   public:
      ML_DSA_ACVP_KAT_KeyGen_Tests() : PK_PQC_ACVP_KAT_KeyGen_Test("ML-DSA", "pubkey/ml_dsa_acvp_keygen.vec", "SEED") {}

   private:
      bool is_available(const std::string& mode) const final { return Botan::ML_DSA_Mode(mode).is_available(); }

      Fixed_Output_RNG rng_for_keygen(const VarMap& vars) const override {
         const auto seed = vars.get_req_bin("SEED");
         return Fixed_Output_RNG(seed);
      }
};

class ML_DSA_ACVP_KAT_SigVer_Tests final : public PK_PQC_ACVP_KAT_SigVer_Test {
   public:
      ML_DSA_ACVP_KAT_SigVer_Tests() : PK_PQC_ACVP_KAT_SigVer_Test("ML-DSA", "pubkey/ml_dsa_acvp_sigver.vec") {}

   private:
      bool is_available(const std::string& mode) const final { return Botan::ML_DSA_Mode(mode).is_available(); }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars, const std::string& params) const override {
         auto pk = std::make_unique<Botan::ML_DSA_PublicKey>(vars.get_req_bin("PK"), Botan::ML_DSA_Mode(params));
         return pk;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ml_dsa_verify", ML_DSA_Verify_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ml_dsa_acvp_keygen", ML_DSA_ACVP_KAT_KeyGen_Tests);
// Currently we cannot use the siggen test because the private seed of the sk is not provided
BOTAN_REGISTER_TEST("pubkey", "ml_dsa_acvp_sigver", ML_DSA_ACVP_KAT_SigVer_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
