/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ED25519)
   #include <botan/ed25519.h>
   #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ED25519)

class Ed25519_Signature_Tests : public PK_Signature_Generation_Test
   {
   public:
      Ed25519_Signature_Tests() : PK_Signature_Generation_Test(
            "Ed25519",
            "pubkey/ed25519.vec",
            "Privkey,Pubkey,Hash,Msg,Signature") {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::vector<uint8_t> privkey = get_req_bin(vars, "Privkey");
         const std::vector<uint8_t> pubkey = get_req_bin(vars, "Pubkey");

         Botan::secure_vector<uint8_t> seed(privkey.begin(), privkey.end());

         std::unique_ptr<Botan::Ed25519_PrivateKey> key(new Botan::Ed25519_PrivateKey(seed));

         if(key->get_public_key() != pubkey)
            throw Test_Error("Invalid Ed25519 key in test data");

         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return get_opt_str(vars, "Hash", "Pure");
         }
   };

BOTAN_REGISTER_TEST("ed25519_sign", Ed25519_Signature_Tests);

#endif

}

}
