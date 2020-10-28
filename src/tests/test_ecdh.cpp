/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDH)
   #include "test_pubkey.h"
   #include <botan/ecdh.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDH)

class ECDH_KAT_Tests final : public PK_Key_Agreement_Test
   {
   public:
      ECDH_KAT_Tests()
         : PK_Key_Agreement_Test(
              "ECDH",
              "pubkey/ecdh.vec",
              "Group,Secret,CounterKey,K",
              "KDF") {}

      std::string default_kdf(const VarMap&) const override
         {
         return "Raw";
         }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& group_id,
            const VarMap& vars) override
         {
         Botan::EC_Group group(group_id);
         const Botan::BigInt secret = vars.get_req_bn("Secret");
         std::unique_ptr<Botan::Private_Key> key(new Botan::ECDH_PrivateKey(Test::rng(), group, secret));
         return key;
         }

      std::vector<uint8_t> load_their_key(const std::string&, const VarMap& vars) override
         {
         return vars.get_req_bin("CounterKey");
         }
   };

class ECDH_Keygen_Tests final : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override
         {
         return { "secp256r1", "secp384r1", "secp521r1",
                  "brainpool256r1", "brainpool384r1", "brainpool512r1", "frp256v1" };
         }
      std::string algo_name() const override
         {
         return "ECDH";
         }
   };


BOTAN_REGISTER_TEST("pubkey", "ecdh_kat", ECDH_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdh_keygen", ECDH_Keygen_Tests);

#endif

}

}
