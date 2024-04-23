/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "tests.h"

#if defined(BOTAN_HAS_HSS_LMS)

   #include <botan/internal/lm_ots.h>
   #include <botan/internal/stl_util.h>

namespace Botan_Tests {

namespace {

/**
 * @brief Test the LMOTS logic of HSS-LMS
 */
class LMOTS_Test final : public Text_Based_Test {
   public:
      LMOTS_Test() : Text_Based_Test("pubkey/lmots.vec", "TypeId,Seed,I,q,Msg,PublicKey,HashSig") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         BOTAN_UNUSED(vars);
         return false;
      }

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result("LMOTS");

         const auto lmots_type_id = vars.get_req_u32("TypeId");
         const auto seed = Botan::LMS_Seed(vars.get_req_bin("Seed"));
         const auto identifier = Botan::LMS_Identifier(vars.get_req_bin("I"));
         const auto q = Botan::LMS_Tree_Node_Idx(vars.get_req_u32("q"));
         const auto msg = Botan::LMS_Message(vars.get_req_bin("Msg"));
         const auto pk_ref = Botan::LMOTS_K(vars.get_req_bin("PublicKey"));
         // To safe file space the signature is only stored in hashed form
         const auto sig_ref = vars.get_req_bin("HashSig");

         auto hash = Botan::HashFunction::create("SHA-256");

         auto type = static_cast<Botan::LMOTS_Algorithm_Type>(lmots_type_id);
         auto params = Botan::LMOTS_Params::create_or_throw(type);

         // Test private/public OTS key creation
         auto sk = Botan::LMOTS_Private_Key(params, identifier, q, seed);
         const auto pk = Botan::LMOTS_Public_Key(sk);
         result.test_is_eq("Public key generation", pk.K(), pk_ref);

         // Test signature creation
         Botan::LMOTS_Signature_Bytes sig(Botan::LMOTS_Signature::size(params));
         sk.sign(sig, msg);
         result.test_is_eq("Signature generation", hash->process<std::vector<uint8_t>>(sig), sig_ref);

         // Test create pubkey from signature
         auto sig_slicer = Botan::BufferSlicer(sig);
         auto sig_obj = Botan::LMOTS_Signature::from_bytes_or_throw(sig_slicer);
         Botan::LMOTS_K pk_from_sig = Botan::lmots_compute_pubkey_from_sig(sig_obj, msg, identifier, q);
         result.test_is_eq("Public key from signature", pk_from_sig, pk_ref);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "lmots", LMOTS_Test);

}  // namespace
}  // namespace Botan_Tests

#endif  // BOTAN_HAS_HSS_LMS
