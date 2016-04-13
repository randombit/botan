/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
  #include <botan/pubkey.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RW)

class RW_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      RW_KAT_Tests() : PK_Signature_Generation_Test(
         "Rabin-Williams",
         "pubkey/rw_sig.vec",
         {"E", "P", "Q", "Msg", "Signature"},
         {"Padding"})
         {}

      std::string default_padding(const VarMap&) const override { return "EMSA2(SHA-1)"; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RW_PrivateKey(Test::rng(), p, q, e));
         return key;
         }

   };

class RW_Verify_Tests : public PK_Signature_Verification_Test
   {
   public:
      RW_Verify_Tests() : PK_Signature_Verification_Test(
         "Rabin-Williams",
         "pubkey/rw_verify.vec",
         {"E", "N", "Msg", "Signature"})
         {}

      std::string default_padding(const VarMap&) const override { return "EMSA2(SHA-1)"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Public_Key> key(new Botan::RW_PublicKey(n, e));
         return key;
         }

   };

BOTAN_REGISTER_TEST("rw_kat", RW_KAT_Tests);
BOTAN_REGISTER_TEST("rw_verify", RW_Verify_Tests);

#endif

}

}
