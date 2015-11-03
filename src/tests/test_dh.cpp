/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include "test_pubkey.h"
  #include <botan/pubkey.h>
  #include <botan/dh.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

class Diffie_Hellman_KAT_Tests : public PK_Key_Agreement_Test
   {
   public:
      Diffie_Hellman_KAT_Tests() : PK_Key_Agreement_Test(
         "Diffie-Hellman",
         Test::data_file("pubkey/dh.vec"),
         {"P", "G", "X", "Y", "Msg", "OutLen", "K"},
         {"KDF"})
         {}

      std::string default_kdf(const VarMap&) { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt x = get_req_bn(vars, "X");

         const Botan::DL_Group grp(p, g);

         std::unique_ptr<Botan::Private_Key> key(new Botan::DH_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::vector<uint8_t> load_their_key(const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt y = get_req_bn(vars, "Y");
         const Botan::DL_Group grp(p, g);

         Botan::DH_PublicKey key(grp, y);
         return key.public_value();
         }
};

BOTAN_REGISTER_TEST("dh_kat", Diffie_Hellman_KAT_Tests);

#endif

}

}

size_t test_dh()
   {
   return Botan_Tests::basic_error_report("dh_kat");
   }
