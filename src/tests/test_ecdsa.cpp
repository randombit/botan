/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include "test_rng.h"

#if defined(BOTAN_HAS_ECDSA)
  #include "test_pubkey.h"
  #include <botan/ecdsa.h>
  #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_Signature_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      ECDSA_Signature_KAT_Tests() : PK_Signature_Generation_Test(
         "ECDSA",
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         "pubkey/ecdsa_rfc6979.vec",
         {"Group", "X", "Hash", "Msg", "Signature"})
#else
         "pubkey/ecdsa_prob.vec",
         {"Group", "X", "Hash", "Msg", "Nonce", "Signature"})
#endif
         {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");
         const BigInt x = get_req_bn(vars, "X");
         Botan::EC_Group group(Botan::OIDS::lookup(group_id));

         std::unique_ptr<Botan::Private_Key> key(new Botan::ECDSA_PrivateKey(Test::rng(), group, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }

#if !defined(BOTAN_HAS_RFC6979)
      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         // probabilistic ecdsa signature generation extracts more random than just the nonce,
         // but the nonce is extracted first
         return new Fixed_Output_Position_RNG(nonce, 1);
         }
#endif
   };

class ECDSA_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "secp256r1", "secp384r1", "secp521r1", "frp256v1" }; }
      std::string algo_name() const override { return "ECDSA"; }
   };

BOTAN_REGISTER_TEST("ecdsa_sign", ECDSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("ecdsa_keygen", ECDSA_Keygen_Tests);

#endif

}

}
