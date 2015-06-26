#include "tests.h"

#if defined(BOTAN_HAS_SRP6)

#include <botan/srp6.h>
#include <iostream>

size_t test_srp6()
   {
   using namespace Botan;

   size_t fails = 0;

   const std::string username = "user";
   const std::string password = "Awellchosen1_to_be_sure_";
   const std::string group_id = "modp/srp/1024";
   const std::string hash_id = "SHA-256";
   auto& rng = test_rng();

   const auto salt = unlock(rng.random_vec(16));

   const BigInt verifier = generate_srp6_verifier(username, password, salt, group_id, hash_id);

   SRP6_Server_Session server;

   const BigInt B = server.step1(verifier, group_id, hash_id, rng);

   auto client = srp6_client_agree(username, password, group_id, hash_id, salt, B, rng);

   const SymmetricKey server_K = server.step2(client.first);

   if(client.second != server_K)
      {
      std::cout << "SRP6 computed different keys" << std::endl;
      ++fails;
      }

   test_report("SRP6", 1, fails);

   return fails;

   }

#else

SKIP_TEST(srp6);

#endif // BOTAN_HAS_SRP6
