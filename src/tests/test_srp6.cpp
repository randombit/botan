/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SRP6)
   #include <botan/srp6.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_SRP6) && defined(BOTAN_HAS_SHA2_32)

class SRP6_Unit_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         Test::Result result("SRP6");

         const std::string username = "user";
         const std::string password = "Awellchosen1_to_be_sure_";
         const std::string group_id = "modp/srp/1024";
         const std::string hash_id = "SHA-256";

         const std::vector<uint8_t> salt = unlock(Test::rng().random_vec(16));

         const Botan::BigInt verifier = Botan::generate_srp6_verifier(username, password, salt, group_id, hash_id);

         Botan::SRP6_Server_Session server;

         const Botan::BigInt B = server.step1(verifier, group_id, hash_id, Test::rng());

         auto client = srp6_client_agree(username, password, group_id, hash_id, salt, B, Test::rng());

         const Botan::SymmetricKey server_K = server.step2(client.first);

         result.test_eq("computed same keys", client.second.bits_of(), server_K.bits_of());
         results.push_back(result);

         return results;
         }
   };

BOTAN_REGISTER_TEST("srp6", SRP6_Unit_Tests);
#endif

}

}
