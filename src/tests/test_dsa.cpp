/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DSA)
   #include <botan/dsa.h>
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DSA)

class DSA_KAT_Tests final : public PK_Signature_Generation_Test
   {
   public:
      DSA_KAT_Tests() : PK_Signature_Generation_Test(
            "DSA",
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
            "pubkey/dsa_rfc6979.vec",
            "P,Q,G,X,Hash,Msg,Signature",
#else
            "pubkey/dsa_prob.vec",
            "P,Q,G,X,Hash,Msg,Nonce,Signature",
#endif
            "") {}

      bool clear_between_callbacks() const override
         {
         return false;
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt q = get_req_bn(vars, "Q");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt x = get_req_bn(vars, "X");

         const Botan::DL_Group grp(p, q, g);

         std::unique_ptr<Botan::Private_Key> key(new Botan::DSA_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }
   };

class DSA_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "dsa/jce/1024" };
         }
      std::string algo_name() const override
         {
         return "DSA";
         }
   };

class DSA_Reduction_Test : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("DSA reduction");

#if defined(BOTAN_HAS_EME_RAW)

         /*
         * Test "Raw" signature of SHA-256 hash using a DSA param set
         * with 160 bit q. Previously DSA would go into an effectively
         * infinite loop due to subtracting a 160 bit integer from a
         * 256 bit integer enough times to make it less than or equal q.
         */
         Botan::DL_Group group("dsa/jce/1024");
         Botan::DSA_PrivateKey dsa(Test::rng(), group);

         Botan::PK_Signer signer(dsa, Test::rng(), "Raw");

         // Standin for a large hash value
         const uint8_t large_hash[32] = { 0xFF, 0xFE, 0xFD, 0xFC, 0 };

         const std::vector<uint8_t> signature =
            signer.sign_message(large_hash, sizeof(large_hash), Test::rng());

         result.test_success("PK_Signer::sign_message returned");

         // Now verify it...
         Botan::PK_Verifier verifier(dsa, "Raw");

         const bool signature_verified =
            verifier.verify_message(large_hash, sizeof(large_hash),
                                    signature.data(), signature.size());

         result.confirm("Signature of large hash value verifies", signature_verified);
#else
         result.test_note("Skipping DSA reduction test due to missing EME_Raw");
#endif

         return std::vector<Test::Result>{result};
         }
   };

BOTAN_REGISTER_TEST("dsa_sign", DSA_KAT_Tests);
BOTAN_REGISTER_TEST("dsa_keygen", DSA_Keygen_Tests);
BOTAN_REGISTER_TEST("dsa_reduction", DSA_Reduction_Test);

#endif

}

}
