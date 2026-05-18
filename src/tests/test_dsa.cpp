/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DSA)
   #include "test_pubkey.h"
   #include <botan/bigint.h>
   #include <botan/dl_group.h>
   #include <botan/dsa.h>
   #include <botan/pk_options.h>
   #include <botan/pubkey.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DSA)

class DSA_KAT_Tests final : public PK_Signature_Generation_Test {
   public:
      DSA_KAT_Tests() :
            PK_Signature_Generation_Test("DSA", "pubkey/dsa_prob.vec", "P,Q,G,X,Hash,Msg,Nonce,Signature", "") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         const Botan::DL_Group group(p, q, g);

         return std::make_unique<Botan::DSA_PrivateKey>(group, x);
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }
};

   #if defined(BOTAN_HAS_RFC6979_GENERATOR)

class DSA_RFC6979_KAT_Tests final : public Text_Based_Test {
   public:
      DSA_RFC6979_KAT_Tests() : Text_Based_Test("pubkey/dsa_rfc6979.vec", "P,Q,G,X,Hash,Msg,Signature") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const std::string hash = vars.get_req_str("Hash");
         const auto msg = vars.get_req_bin("Msg");
         const auto expected_sig = vars.get_req_bin("Signature");

         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         Test::Result result("DSA RFC6979 " + hash);

         const Botan::DL_Group group(p, q, g);
         const Botan::DSA_PrivateKey priv_key(group, x);

         Botan::PK_Signer signer(
            priv_key, this->rng(), Botan::PK_Signature_Options(hash).with_deterministic_signature());

         const auto sig = signer.sign_message(msg, this->rng());
         result.test_bin_eq("RFC6979 signature matches KAT", sig, expected_sig);

         const auto pub = priv_key.public_key();
         Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options(hash));
         result.test_is_true("Signature verifies", verifier.verify_message(msg, sig));

         return result;
      }
};

   #endif

class DSA_KAT_Verification_Tests final : public PK_Signature_Verification_Test {
   public:
      DSA_KAT_Verification_Tests() :
            PK_Signature_Verification_Test("DSA", "pubkey/dsa_rfc6979.vec", "P,Q,G,X,Hash,Msg,Signature", "") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         const Botan::DL_Group grp(p, q, g);

         const Botan::DSA_PrivateKey priv_key(grp, x);

         return priv_key.public_key();
      }

      std::string default_padding(const VarMap& vars) const override { return vars.get_req_str("Hash"); }
};

class DSA_Verification_Tests final : public PK_Signature_Verification_Test {
   public:
      DSA_Verification_Tests() :
            PK_Signature_Verification_Test("DSA", "pubkey/dsa_verify.vec", "P,Q,G,Y,Msg,Signature") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt y = vars.get_req_bn("Y");

         const Botan::DL_Group group(p, q, g);

         return std::make_unique<Botan::DSA_PublicKey>(group, y);
      }

      std::string default_padding(const VarMap& /*unused*/) const override { return "Raw"; }
};

class DSA_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"dsa/jce/1024"}; }

      std::string algo_name() const override { return "DSA"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::DSA_PublicKey>(Botan::DL_Group::from_name(keygen_params),
                                                       Botan::BigInt(raw_pk));
      }
};

BOTAN_REGISTER_TEST("pubkey", "dsa_kat_sign", DSA_KAT_Tests);
   #if defined(BOTAN_HAS_RFC6979_GENERATOR)
BOTAN_REGISTER_TEST("pubkey", "dsa_rfc6979_sign", DSA_RFC6979_KAT_Tests);
   #endif
BOTAN_REGISTER_TEST("pubkey", "dsa_kat_verify", DSA_KAT_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "dsa_misc_verify", DSA_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "dsa_keygen", DSA_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
