/*
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "tests.h"

#if defined(BOTAN_HAS_HSS_LMS)

   #include <botan/internal/lms.h>
   #include <botan/internal/stl_util.h>

namespace Botan_Tests {

namespace {

/**
 * @brief Test the LMS logic of HSS-LMS
 */
class LMS_Test final : public Text_Based_Test {
   public:
      LMS_Test() : Text_Based_Test("pubkey/lms.vec", "Seed,Msg,q,PublicKey,HashSig") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         BOTAN_UNUSED(vars);
         return false;
      }

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result("LMS");

         const auto seed = Botan::LMS_Seed(vars.get_req_bin("Seed"));
         const auto msg = Botan::LMS_Message(vars.get_req_bin("Msg"));
         const auto q = Botan::LMS_Tree_Node_Idx(vars.get_req_u32("q"));
         const auto pk_ref = vars.get_req_bin("PublicKey");
         // To safe file space the signature is only stored in hashed form
         const auto hashed_sig_ref = vars.get_req_bin("HashSig");

         auto hash = Botan::HashFunction::create("SHA-256");

         auto lms_pk_ref_slicer = Botan::BufferSlicer(pk_ref);
         Botan::LMS_PublicKey lms_pk_ref = Botan::LMS_PublicKey::from_bytes_or_throw(lms_pk_ref_slicer);

         // Test public key creation
         auto lms_sk =
            Botan::LMS_PrivateKey(lms_pk_ref.lms_params(), lms_pk_ref.lmots_params(), lms_pk_ref.identifier(), seed);
         auto pub_key = Botan::LMS_PublicKey(lms_sk);

         result.test_is_eq("Public key generation", pub_key.to_bytes(), pk_ref);

         // Test signature creation and verification
         auto sk =
            Botan::LMS_PrivateKey(lms_pk_ref.lms_params(), lms_pk_ref.lmots_params(), lms_pk_ref.identifier(), seed);
         Botan::LMS_Signature_Bytes sig(Botan::LMS_Signature::size(lms_pk_ref.lms_params(), lms_pk_ref.lmots_params()));
         auto pk_from_sig = sk.sign_and_get_pk(sig, q, msg);
         result.test_is_eq("Signature creation", hash->process<std::vector<uint8_t>>(sig), hashed_sig_ref);

         auto sig_slicer = Botan::BufferSlicer(sig);
         auto sig_obj = Botan::LMS_Signature::from_bytes_or_throw(sig_slicer);
         result.confirm("Signature verification", pub_key.verify_signature(msg, sig_obj));

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "lms", LMS_Test);

}  // namespace
}  // namespace Botan_Tests

#endif  // BOTAN_HAS_HSS_LMS
