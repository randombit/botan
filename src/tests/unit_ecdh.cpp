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
   #include <botan/ecdh.h>
   #include <botan/pubkey.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDH)
class ECDH_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_ecdh_normal_derivation(this->rng()));

         return results;
      }

   private:
      static Test::Result test_ecdh_normal_derivation(Botan::RandomNumberGenerator& rng) {
         Test::Result result("ECDH key exchange");

         const auto params = {"secp256r1", "secp384r1", "secp521r1", "brainpool256r1"};

         for(const auto& param : params) {
            try {
               const auto dom_pars = Botan::EC_Group::from_name(param);
               Botan::ECDH_PrivateKey private_a(rng, dom_pars);
               Botan::ECDH_PrivateKey private_b(rng, dom_pars);

               Botan::PK_Key_Agreement ka(private_a, rng, "KDF2(SHA-512)");
               Botan::PK_Key_Agreement kb(private_b, rng, "KDF2(SHA-512)");

               Botan::SymmetricKey alice_key = ka.derive_key(32, private_b.public_value());
               Botan::SymmetricKey bob_key = kb.derive_key(32, private_a.public_value());

               if(!result.test_eq("same derived key", alice_key.bits_of(), bob_key.bits_of())) {
                  result.test_note("Keys where " + alice_key.to_string() + " and " + bob_key.to_string());
               }
            } catch(Botan::Lookup_Error& e) {
               result.test_note("Skipping because ", e.what());
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecdh_unit", ECDH_Unit_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
