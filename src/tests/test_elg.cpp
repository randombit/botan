/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ELGAMAL)

class ElGamal_KAT_Tests : public PK_Encryption_Decryption_Test
   {
   public:
      ElGamal_KAT_Tests() : PK_Encryption_Decryption_Test(
         "ElGamal",
         Test::data_file("pubkey/elgamal.vec"),
         {"P", "G", "X", "Msg", "Nonce", "Ciphertext"},
         {"Padding"})
         {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt g = get_req_bn(vars, "G");
         const BigInt x = get_req_bn(vars, "X");

         const DL_Group grp(p, g);

         std::unique_ptr<Botan::Private_Key> key(new Botan::ElGamal_PrivateKey(Test::rng(), grp, x));
         return key;
         }
   };

BOTAN_REGISTER_TEST("elgamal_kat", ElGamal_KAT_Tests);

#endif

}

}

size_t test_elgamal()
   {
   return Botan_Tests::basic_error_report("elgamal_kat");
   }
