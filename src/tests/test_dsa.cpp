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

class DSA_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      DSA_KAT_Tests() : PK_Signature_Generation_Test(
         "DSA",
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         "pubkey/dsa_rfc6979.vec",
         {"P", "Q", "G", "X", "Hash", "Msg", "Signature"})
#else
         "pubkey/dsa_prob.vec",
         {"P", "Q", "G", "X", "Hash", "Msg", "Nonce", "Signature"})
#endif
         {}

      bool clear_between_callbacks() const override { return false; }

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

class DSA_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "dsa/jce/1024", "dsa/botan/2048" }; }

      std::unique_ptr<Botan::Private_Key> make_key(Botan::RandomNumberGenerator& rng,
                                                   const std::string& param) const override
         {
         Botan::DL_Group group(param);
         std::unique_ptr<Botan::Private_Key> key(new Botan::DSA_PrivateKey(rng, group));
         return key;
         }
   };

BOTAN_REGISTER_TEST("dsa_kat", DSA_KAT_Tests);
BOTAN_REGISTER_TEST("dsa_keygen", DSA_Keygen_Tests);

#endif

}

}
