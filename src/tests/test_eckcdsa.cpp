/*
* (C) 2016 René Korthaus, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include "test_rng.h"

#if defined(BOTAN_HAS_ECKCDSA)
  #include "test_pubkey.h"
  #include <botan/eckcdsa.h>
  #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECKCDSA)

class ECKCDSA_Signature_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      ECKCDSA_Signature_KAT_Tests() : PK_Signature_Generation_Test(
         "ECKCDSA",
         "pubkey/eckcdsa.vec",
         {"Group", "X", "Hash", "Msg", "Nonce", "Signature"})
         {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");
         const BigInt x = get_req_bn(vars, "X");
         Botan::EC_Group group(Botan::OIDS::lookup(group_id));

         std::unique_ptr<Botan::Private_Key> key(new Botan::ECKCDSA_PrivateKey(Test::rng(), group, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }

      Botan::RandomNumberGenerator* test_rng(const std::vector<uint8_t>& nonce) const override
         {
         // eckcdsa signature generation extracts more random than just the nonce,
         // but the nonce is extracted first
         return new Fixed_Output_Position_RNG(nonce, 1);
         }
   };

class ECKCDSA_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "secp256r1", "secp384r1", "secp521r1" }; }

      std::unique_ptr<Botan::Private_Key> make_key(Botan::RandomNumberGenerator& rng,
                                                   const std::string& param) const override
         {
         Botan::EC_Group group(param);
         return std::unique_ptr<Botan::Private_Key>(new Botan::ECKCDSA_PrivateKey(rng, group));
         }
   };

BOTAN_REGISTER_TEST("eckcdsa", ECKCDSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("eckcdsa_keygen", ECKCDSA_Keygen_Tests);

#endif

}

}
