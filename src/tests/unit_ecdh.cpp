/*
* ECDH tests
*
* (C) 2007 Manuel Hartl (hartl@flexsecure.de)
*     2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDH)
  #include <botan/pubkey.h>
  #include <botan/ecdh.h>
  #include <botan/der_enc.h>
  #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDH)
class ECDH_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_ecdh_normal_derivation());

         return results;
         }
   private:

      Test::Result test_ecdh_normal_derivation()
         {
         Test::Result result("ECDH kex");

         std::vector<std::string> oids = { "1.2.840.10045.3.1.7",
                                           "1.3.132.0.8",
                                           "1.2.840.10045.3.1.1" };
         try
            {
            for(auto&& oid : oids)
               {
               Botan::EC_Group dom_pars(Botan::OIDS::lookup(oid));
               Botan::ECDH_PrivateKey private_a(Test::rng(), dom_pars);
               Botan::ECDH_PrivateKey private_b(Test::rng(), dom_pars);

               Botan::PK_Key_Agreement ka(private_a, "KDF2(SHA-512)");
               Botan::PK_Key_Agreement kb(private_b, "KDF2(SHA-512)");

               Botan::SymmetricKey alice_key = ka.derive_key(32, private_b.public_value());
               Botan::SymmetricKey bob_key = kb.derive_key(32, private_a.public_value());

               if(!result.test_eq("same derived key", alice_key.bits_of(), bob_key.bits_of()))
                  {
                  result.test_note("Keys where " + alice_key.as_string() + " and " + bob_key.as_string());
                  }
               }
            }
         catch(Botan::Lookup_Error&)
            {
            result.test_note("Skipping due to missing KFD2 or SHA-512");
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("ecdh_unit", ECDH_Unit_Tests);

#endif

}

}
