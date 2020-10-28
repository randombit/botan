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
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt x = vars.get_req_bn("X");

         const Botan::DL_Group grp(p, q, g);

         std::unique_ptr<Botan::Private_Key> key(new Botan::DSA_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + vars.get_req_str("Hash") + ")";
         }
   };

class DSA_Verification_Tests final : public PK_Signature_Verification_Test
   {
   public:
      DSA_Verification_Tests() : PK_Signature_Verification_Test(
            "DSA",
            "pubkey/dsa_verify.vec",
            "P,Q,G,Y,Msg,Signature") {}

      bool clear_between_callbacks() const override
         {
         return false;
         }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const Botan::BigInt p = vars.get_req_bn("P");
         const Botan::BigInt q = vars.get_req_bn("Q");
         const Botan::BigInt g = vars.get_req_bn("G");
         const Botan::BigInt y = vars.get_req_bn("Y");

         const Botan::DL_Group grp(p, q, g);

         std::unique_ptr<Botan::Public_Key> key(new Botan::DSA_PublicKey(grp, y));
         return key;
         }

      std::string default_padding(const VarMap&) const override
         {
         return "Raw";
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

BOTAN_REGISTER_TEST("pubkey", "dsa_sign", DSA_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "dsa_verify", DSA_Verification_Tests);
BOTAN_REGISTER_TEST("pubkey", "dsa_keygen", DSA_Keygen_Tests);

#endif

}

}
