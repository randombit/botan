/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#include <botan/rng.h>

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   #include <botan/ec_group.h>
   #include <botan/ec_scalar.h>
   #include <botan/spake2p.h>
#endif

#if defined(BOTAN_HAS_SRP6)
   #include <botan/bigint.h>
   #include <botan/dl_group.h>
   #include <botan/srp6.h>
   #include <botan/symkey.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_CLI {

namespace {

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)

class PerfTest_Spake2p final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         struct Suite {
               const char* name;
               const char* group;
               Botan::SPAKE2p::SystemParameters (*params)();
         };

         const Suite suites[] = {
            {"SPAKE2+ P256-SHA256", "secp256r1", Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256},
            {"SPAKE2+ P384-SHA512", "secp384r1", Botan::SPAKE2p::SystemParameters::rfc9383_p384_sha512},
            {"SPAKE2+ P521-SHA512", "secp521r1", Botan::SPAKE2p::SystemParameters::rfc9383_p521_sha512},
         };

         auto& rng = config.rng();
         const auto msec = config.runtime();

         const std::vector<uint8_t> prover_id = {'c', 'l', 'i', 'e', 'n', 't'};
         const std::vector<uint8_t> verifier_id = {'s', 'e', 'r', 'v', 'e', 'r'};

         for(const auto& suite : suites) {
            if(!Botan::EC_Group::supports_named_group(suite.group)) {
               continue;
            }

            const auto params = suite.params();

            // Password hashing (Argon2id) is benchmarked separately; here we
            // use random scalars so the timings cover just the protocol itself
            const auto secret = Botan::SPAKE2p::ProverSecret::from_prehashed(
               Botan::EC_Scalar::random(params.group(), rng), Botan::EC_Scalar::random(params.group(), rng));
            const auto record = secret.registration_record(rng);

            auto share_timer = config.make_timer(suite.name, 1, "prover share");
            auto respond_timer = config.make_timer(suite.name, 1, "verifier respond");
            auto confirm_timer = config.make_timer(suite.name, 1, "prover confirm");

            while(share_timer->under(msec) && respond_timer->under(msec) && confirm_timer->under(msec)) {
               share_timer->start();
               Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id);
               const auto share_p = prover.generate_message(rng);
               share_timer->stop();

               respond_timer->start();
               Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id);
               const auto response = verifier.process_message(share_p, rng);
               respond_timer->stop();

               confirm_timer->start();
               const auto confirm_p = prover.process_message(response, rng);
               confirm_timer->stop();

               verifier.verify_confirmation(confirm_p);

               if(prover.shared_secret() != verifier.shared_secret()) {
                  config.error_output() << "SPAKE2+ shared secret mismatch\n";
               }
            }

            config.record_result(*share_timer);
            config.record_result(*respond_timer);
            config.record_result(*confirm_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("SPAKE2+", PerfTest_Spake2p);

#endif

#if defined(BOTAN_HAS_SRP6)

class PerfTest_Srp6 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const std::string username = "user";
         const std::string password = "password";
         const std::string hash = "SHA-256";

         auto& rng = config.rng();
         const auto msec = config.runtime();

         for(const std::string group_id : {"modp/srp/2048", "modp/srp/3072", "modp/srp/4096", "modp/srp/6144"}) {
            const auto group = Botan::DL_Group::from_name(group_id);
            const size_t x_bits = group.exponent_bits();

            const std::string name = Botan::fmt("SRP6-{}", group_id.substr(group_id.find_last_of('/') + 1));

            std::vector<uint8_t> salt(16);
            rng.randomize(salt);

            const auto verifier = Botan::srp6_generate_verifier(username, password, salt, group, hash);

            auto step1_timer = config.make_timer(name, 1, "server step1");
            auto client_timer = config.make_timer(name, 1, "client agree");
            auto step2_timer = config.make_timer(name, 1, "server step2");

            while(step1_timer->under(msec) && client_timer->under(msec) && step2_timer->under(msec)) {
               Botan::SRP6_Server_Session server;

               step1_timer->start();
               const Botan::BigInt B = server.step1(verifier, group, hash, x_bits, rng);
               step1_timer->stop();

               client_timer->start();
               const auto [A, client_key] =
                  Botan::srp6_client_agree(username, password, group, hash, salt, B, x_bits, rng);
               client_timer->stop();

               step2_timer->start();
               const auto server_key = server.step2(A);
               step2_timer->stop();

               if(client_key != server_key) {
                  config.error_output() << "SRP6 shared secret mismatch\n";
               }
            }

            config.record_result(*step1_timer);
            config.record_result(*client_timer);
            config.record_result(*step2_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("SRP6", PerfTest_Srp6);

#endif

}  // namespace

}  // namespace Botan_CLI
