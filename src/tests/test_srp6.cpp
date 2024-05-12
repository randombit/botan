/*
* (C) 2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SRP6)
   #include "test_rng.h"
   #include <botan/dl_group.h>
   #include <botan/hash.h>
   #include <botan/srp6.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_SRP6)

class SRP6_KAT_Tests final : public Text_Based_Test {
   public:
      SRP6_KAT_Tests() : Text_Based_Test("srp6a.vec", "Hash,N,g,I,P,s,v,a,b,A,B,S") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
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
         const auto exp_S = Botan::SymmetricKey(vars.get_req_bin("S"));

         const std::string group_id = Botan::srp6_group_identifier(N, g);
         if(group_id.empty()) {
            throw Test_Error("Unknown SRP group used in test data");
         }

         Test::Result result("SRP6a " + group_id);

         if(Botan::HashFunction::create(hash) == nullptr) {
            result.test_note("Skipping test as hash function not available");
            return result;
         }

         if(N.bits() >= 4096 && !Test::run_long_tests()) {
            result.test_note("Skipping test with long SRP modulus");
            return result;
         }

         Botan::DL_Group group(group_id);

         const Botan::BigInt v = Botan::srp6_generate_verifier(username, password, salt, group_id, hash);
         result.test_eq("SRP verifier", v, exp_v);

         Botan::SRP6_Server_Session server;

         const size_t b_bits = Botan::BigInt::from_bytes(b).bits();
         Fixed_Output_RNG b_rng(b);
         const Botan::BigInt B = server.step1(v, group, hash, b_bits, b_rng);
         result.test_eq("SRP B", B, exp_B);

         const size_t a_bits = Botan::BigInt::from_bytes(a).bits();
         Fixed_Output_RNG a_rng(a);
         const auto srp_resp = Botan::srp6_client_agree(username, password, group, hash, salt, B, a_bits, a_rng);
         result.test_eq("SRP A", srp_resp.first, exp_A);

         const auto S = server.step2(srp_resp.first);

         result.test_eq("SRP client S", srp_resp.second, exp_S);
         result.test_eq("SRP server S", S, exp_S);

         return result;
      }
};

BOTAN_REGISTER_TEST("pake", "srp6_kat", SRP6_KAT_Tests);

   #if defined(BOTAN_HAS_SHA2_32)

class SRP6_RT_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         const std::string username = "user";
         const std::string password = "Awellchosen1_to_be_sure_";
         const std::string hash_id = "SHA-256";

         for(size_t b : {1024, 1536, 2048, 3072, 4096, 6144, 8192}) {
            if(b >= 4096 && !Test::run_long_tests()) {
               continue;
            }

            const std::string group_id = "modp/srp/" + std::to_string(b);
            Test::Result result("SRP6 " + group_id);

            result.start_timer();

            const size_t trials = 8192 / b;

            for(size_t t = 0; t != trials; ++t) {
               std::vector<uint8_t> salt;
               this->rng().random_vec(salt, 16);

               const Botan::BigInt verifier =
                  Botan::srp6_generate_verifier(username, password, salt, group_id, hash_id);

               Botan::SRP6_Server_Session server;

               const Botan::BigInt B = server.step1(verifier, group_id, hash_id, this->rng());

               auto client = srp6_client_agree(username, password, group_id, hash_id, salt, B, this->rng());

               const Botan::SymmetricKey server_K = server.step2(client.first);

               result.test_eq("computed same keys", client.second.bits_of(), server_K.bits_of());
            }
            result.end_timer();
            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pake", "srp6_rt", SRP6_RT_Tests);

   #endif

#endif

}  // namespace

}  // namespace Botan_Tests
