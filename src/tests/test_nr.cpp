/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

class NR_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      NR_KAT_Tests() : PK_Signature_Generation_Test(
         "Nyberg-Rueppel",
         Test::data_file("pubkey/nr.vec"),
         {"P", "Q", "G", "X", "Hash", "Nonce", "Msg", "Signature"}, {}, false)
         {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt g = get_req_bn(vars, "G");
         const BigInt x = get_req_bn(vars, "X");

         const DL_Group grp(p, q, g);

         std::unique_ptr<Botan::Private_Key> key(new Botan::NR_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }
   };

BOTAN_REGISTER_TEST("nr_kat", NR_KAT_Tests);

#endif

}

}

size_t test_nr()
   {
   return Botan_Tests::basic_error_report("nr_kat");
   }
