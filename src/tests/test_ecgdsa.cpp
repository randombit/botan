/*
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include "test_rng.h"

#if defined(BOTAN_HAS_ECGDSA)
   #include "test_pubkey.h"
   #include <botan/ecgdsa.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECGDSA)

class ECGDSA_Signature_KAT_Tests final : public PK_Signature_Generation_Test
   {
   public:
      ECGDSA_Signature_KAT_Tests() : PK_Signature_Generation_Test(
            "ECGDSA",
            "pubkey/ecgdsa.vec",
            "Group,X,Hash,Msg,Nonce,Signature") {}

      bool clear_between_callbacks() const override
         {
         return false;
         }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::string group_id = vars.get_req_str("Group");
         const BigInt x = vars.get_req_bn("X");
         Botan::EC_Group group(Botan::OID::from_string(group_id));

         std::unique_ptr<Botan::Private_Key> key(new Botan::ECGDSA_PrivateKey(Test::rng(), group, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + vars.get_req_str("Hash") + ")";
         }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         // ecgdsa signature generation extracts more random than just the nonce,
         // but the nonce is extracted first
         return new Fixed_Output_Position_RNG(nonce, 1);
         }
   };

class ECGDSA_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "secp256r1", "secp384r1", "secp521r1" };
         }
      std::string algo_name() const override
         {
         return "ECGDSA";
         }
   };

BOTAN_REGISTER_TEST("pubkey", "ecgdsa_sign", ECGDSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecgdsa_keygen", ECGDSA_Keygen_Tests);

#endif

}

}
