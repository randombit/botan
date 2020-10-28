/*
* (C) 2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SRP6)
   #include <botan/srp6.h>
   #include <botan/hash.h>
   #include <botan/dl_group.h>
   #include "test_rng.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_SRP6)

class SRP6_KAT_Tests final : public Text_Based_Test
   {
   public:
      SRP6_KAT_Tests() : Text_Based_Test("srp6a.vec", "Hash,N,g,I,P,s,v,a,b,A,B,S") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("SRP6a");

         const std::string hash = vars.get_req_str("Hash");
         const std::string username = vars.get_req_str("I");
         const std::string password = vars.get_req_str("P");
         const std::vector<uint8_t> salt = vars.get_req_bin("s");
         const BigInt N = vars.get_req_bn("N");
         const BigInt g = vars.get_req_bn("g");
         const BigInt exp_v = vars.get_req_bn("v");
         const std::vector<uint8_t> a = vars.get_req_bin("a");
         const std::vector<uint8_t> b = vars.get_req_bin("b");
         const BigInt exp_A = vars.get_req_bn("A");
         const BigInt exp_B = vars.get_req_bn("B");
         const std::vector<uint8_t> exp_S = vars.get_req_bin("S");

         if(Botan::HashFunction::create(hash) == nullptr)
            {
            result.test_note("Skipping test as hash function not available");
            return result;
            }

         if(Test::run_long_tests() == false && N.bits() >= 4096)
            {
            result.test_note("Skipping test with long SRP modulus");
            return result;
            }

         const std::string group_id = Botan::srp6_group_identifier(N, g);

         result.test_ne("Known SRP group", group_id, "");

         Botan::DL_Group group(group_id);

         const Botan::BigInt v = Botan::generate_srp6_verifier(username, password, salt, group_id, hash);
         result.test_eq("SRP verifier", v, exp_v);

         Botan::SRP6_Server_Session server;

         const size_t b_bits = Botan::BigInt(b).bits();
         Fixed_Output_RNG b_rng(b);
         const Botan::BigInt B = server.step1(v, group, hash, b_bits, b_rng);
         result.test_eq("SRP B", B, exp_B);

         const size_t a_bits = Botan::BigInt(a).bits();
         Fixed_Output_RNG a_rng(a);
         const auto srp_resp = Botan::srp6_client_agree(username, password, group, hash, salt, B, a_bits, a_rng);
         result.test_eq("SRP A", srp_resp.first, exp_A);

         const auto S = server.step2(srp_resp.first);

         result.test_eq("SRP client and server agree", srp_resp.second, S);

         result.test_eq("SRP S", srp_resp.second.bits_of(), exp_S);

         return result;
         }
   };

BOTAN_REGISTER_TEST("pake", "srp6_kat", SRP6_KAT_Tests);

#if defined(BOTAN_HAS_SHA2_32)

class SRP6_RT_Tests final : public Test
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

         std::vector<uint8_t> salt;
         Test::rng().random_vec(salt, 16);

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

BOTAN_REGISTER_TEST("pake", "srp6", SRP6_RT_Tests);

#endif

#endif

}

}
