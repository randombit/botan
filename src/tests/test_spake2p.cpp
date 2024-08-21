/*
* (C) 2024,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   #include "test_rng.h"
   #include <botan/exceptn.h>
   #include <botan/spake2p.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)

std::optional<Botan::SPAKE2p::SystemParameters> spake2p_params(const std::string& group_name,
                                                               const std::string& hash_fn) {
   using Botan::SPAKE2p::SystemParameters;

   if(!Botan::EC_Group::supports_named_group(group_name)) {
      return std::nullopt;
   }

   if(group_name == "secp256r1" && hash_fn == "SHA-256") {
      return SystemParameters::rfc9383_p256_sha256();
   } else if(group_name == "secp256r1" && hash_fn == "SHA-512") {
      return SystemParameters::rfc9383_p256_sha512();
   } else if(group_name == "secp384r1" && hash_fn == "SHA-256") {
      return SystemParameters::rfc9383_p384_sha256();
   } else if(group_name == "secp384r1" && hash_fn == "SHA-512") {
      return SystemParameters::rfc9383_p384_sha512();
   } else if(group_name == "secp521r1" && hash_fn == "SHA-512") {
      return SystemParameters::rfc9383_p521_sha512();
   } else {
      throw Test_Error("Unexpected group/hash combination in SPAKE2+ test data");
   }
}

std::vector<uint8_t> cat_bin(std::vector<uint8_t> a, const std::vector<uint8_t>& b) {
   a.insert(a.end(), b.begin(), b.end());
   return a;
}

class SPAKE2p_KAT_Tests final : public Text_Based_Test {
   public:
      SPAKE2p_KAT_Tests() :
            Text_Based_Test(
               "pake/spake2p.vec",
               "Group,Hash,Context,ProverId,VerifierId,W0,W1,L,X,ShareP,Y,ShareV,ConfirmP,ConfirmV,Shared") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("SPAKE2+ KAT");

         const auto params = spake2p_params(vars.get_req_str("Group"), vars.get_req_str("Hash"));
         if(!params) {
            result.test_note("Skipping test due to unavailable group");
            return result;
         }

         const auto context = vars.get_req_bin("Context");
         const auto prover_id = vars.get_req_bin("ProverId");
         const auto verifier_id = vars.get_req_bin("VerifierId");
         const auto w0_bytes = vars.get_req_bin("W0");
         const auto w1_bytes = vars.get_req_bin("W1");
         const auto exp_record = cat_bin(w0_bytes, vars.get_req_bin("L"));
         const auto exp_share_p = vars.get_req_bin("ShareP");
         const auto exp_verifier_msg = cat_bin(vars.get_req_bin("ShareV"), vars.get_req_bin("ConfirmV"));
         const auto exp_confirm_p = vars.get_req_bin("ConfirmP");
         const auto exp_shared = vars.get_req_bin("Shared");

         const auto& group = params->group();

         const auto w0 = Botan::EC_Scalar::deserialize(group, w0_bytes).value();
         const auto w1 = Botan::EC_Scalar::deserialize(group, w1_bytes).value();

         const auto secret = Botan::SPAKE2p::ProverSecret::from_prehashed(w0, w1);
         result.test_bin_eq("Prover secret serialization", secret.serialize(), cat_bin(w0_bytes, w1_bytes));

         const auto record = secret.registration_record(this->rng());
         result.test_bin_eq("Registration record", record.serialize(), exp_record);

         const auto record2 = Botan::SPAKE2p::RegistrationRecord::deserialize(*params, exp_record);
         result.test_bin_eq("Registration record deserialization", record2.serialize(), exp_record);

         Botan::SPAKE2p::ProverContext prover(*params, secret, prover_id, verifier_id, context);
         Botan::SPAKE2p::VerifierContext verifier(*params, record2, prover_id, verifier_id, context);

         Fixed_Output_RNG x_rng(this->rng());
         x_rng.add_entropy(vars.get_req_bin("X"));
         const auto share_p = prover.generate_message(x_rng);
         result.test_bin_eq("shareP", share_p, exp_share_p);
         result.test_sz_eq("share size", share_p.size(), params->share_size());

         Fixed_Output_RNG y_rng(this->rng());
         y_rng.add_entropy(vars.get_req_bin("Y"));
         const auto verifier_msg = verifier.process_message(share_p, y_rng);
         result.test_bin_eq("shareV || confirmV", verifier_msg, exp_verifier_msg);

         const auto confirm_p = prover.process_message(verifier_msg, this->rng());
         result.test_bin_eq("confirmP", confirm_p, exp_confirm_p);
         result.test_sz_eq("confirmation size", confirm_p.size(), params->confirmation_size());
         result.test_bin_eq("Prover shared secret", prover.shared_secret(), exp_shared);

         result.test_no_throw("Prover confirmation accepted", [&]() { verifier.verify_confirmation(confirm_p); });
         result.test_bin_eq("Verifier shared secret", verifier.shared_secret(), exp_shared);

         return result;
      }
};

BOTAN_REGISTER_TEST("pake", "spake2p_kat", SPAKE2p_KAT_Tests);

class SPAKE2p_RT_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_exchange("P256-SHA256", Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256()));
         results.push_back(test_exchange("P256-SHA512", Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha512()));

         if(Botan::EC_Group::supports_named_group("secp384r1")) {
            results.push_back(test_exchange("P384-SHA256", Botan::SPAKE2p::SystemParameters::rfc9383_p384_sha256()));
            results.push_back(test_exchange("P384-SHA512", Botan::SPAKE2p::SystemParameters::rfc9383_p384_sha512()));
         }

         if(Botan::EC_Group::supports_named_group("secp521r1")) {
            results.push_back(test_exchange("P521-SHA512", Botan::SPAKE2p::SystemParameters::rfc9383_p521_sha512()));
         }

         results.push_back(test_custom_params());

         return results;
      }

   private:
      Test::Result test_exchange(const std::string& name, const Botan::SPAKE2p::SystemParameters& params) {
         Test::Result result("SPAKE2+ round trip " + name);
         result.start_timer();

         const std::vector<uint8_t> prover_id = {'c', 'l', 'i', 'e', 'n', 't'};
         const std::vector<uint8_t> verifier_id = {'s', 'e', 'r', 'v', 'e', 'r'};
         const auto context = this->rng().random_vec(16);

         const auto secret = random_secret(params);
         const auto record = secret.registration_record(this->rng());

         // Test that serialization of the secret and record round trips
         const auto secret2 = Botan::SPAKE2p::ProverSecret::deserialize(params, secret.serialize());
         result.test_bin_eq("Prover secret roundtrips", secret2.serialize(), secret.serialize());
         const auto record2 = Botan::SPAKE2p::RegistrationRecord::deserialize(params, record.serialize());
         result.test_bin_eq("Registration record roundtrips", record2.serialize(), record.serialize());

         // A successful exchange, using the deserialized secret and record
         {
            Botan::SPAKE2p::ProverContext prover(params, secret2, prover_id, verifier_id, context);
            Botan::SPAKE2p::VerifierContext verifier(params, record2, prover_id, verifier_id, context);

            result.test_throws<Botan::Invalid_State>("Prover cannot process before generating",
                                                     [&]() { prover.process_message({}, this->rng()); });
            result.test_throws<Botan::Invalid_State>("No prover secret before completion",
                                                     [&]() { prover.shared_secret(); });

            const auto share_p = prover.generate_message(this->rng());
            result.test_throws<Botan::Invalid_State>("Prover share can be generated only once",
                                                     [&]() { prover.generate_message(this->rng()); });

            const auto verifier_msg = verifier.process_message(share_p, this->rng());
            result.test_throws<Botan::Invalid_State>("Verifier processes only one share",
                                                     [&]() { verifier.process_message(share_p, this->rng()); });
            result.test_throws<Botan::Invalid_State>("No verifier secret before confirmation",
                                                     [&]() { verifier.shared_secret(); });

            const auto confirm_p = prover.process_message(verifier_msg, this->rng());
            verifier.verify_confirmation(confirm_p);

            result.test_bin_eq("Shared secrets match", prover.shared_secret(), verifier.shared_secret());
         }

         // An exchange where the verifier explicitly skips the prover's confirmation
         {
            Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id, context);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id, context);

            result.test_throws<Botan::Invalid_State>("Cannot skip confirmation before responding",
                                                     [&]() { verifier.skip_confirmation(); });

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            const auto confirm_p = prover.process_message(verifier_msg, this->rng());

            verifier.skip_confirmation();
            result.test_bin_eq("Shared secrets match", prover.shared_secret(), verifier.shared_secret());

            // Having skipped, the confirmation can no longer be checked
            result.test_throws<Botan::Invalid_State>("Cannot verify confirmation after skipping",
                                                     [&]() { verifier.verify_confirmation(confirm_p); });
         }

         // A prover with the wrong password fails during confirmation
         {
            const auto wrong_secret = random_secret(params);
            Botan::SPAKE2p::ProverContext prover(params, wrong_secret, prover_id, verifier_id, context);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id, context);

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            result.test_throws<Botan::Invalid_Authentication_Tag>(
               "Wrong password is detected", [&]() { prover.process_message(verifier_msg, this->rng()); });

            // After a failure the context cannot be used further
            result.test_throws<Botan::Invalid_State>("No reuse after failure",
                                                     [&]() { prover.process_message(verifier_msg, this->rng()); });
            result.test_throws<Botan::Invalid_State>("No secret after failure", [&]() { prover.shared_secret(); });
         }

         // A context or identity mismatch fails during confirmation
         {
            Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id, context);
            const auto bad_context = this->rng().random_vec(16);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id, bad_context);

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            result.test_throws<Botan::Invalid_Authentication_Tag>(
               "Context mismatch is detected", [&]() { prover.process_message(verifier_msg, this->rng()); });
         }

         {
            Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id, context);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, {}, context);

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            result.test_throws<Botan::Invalid_Authentication_Tag>(
               "Identity mismatch is detected", [&]() { prover.process_message(verifier_msg, this->rng()); });
         }

         // A tampered prover confirmation is rejected by the verifier
         {
            Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id, context);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id, context);

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            auto confirm_p = prover.process_message(verifier_msg, this->rng());
            confirm_p[0] ^= 0x01;
            result.test_throws<Botan::Invalid_Authentication_Tag>("Tampered confirmation is detected",
                                                                  [&]() { verifier.verify_confirmation(confirm_p); });
            result.test_throws<Botan::Invalid_State>("No secret after failure", [&]() { verifier.shared_secret(); });
            result.test_throws<Botan::Invalid_State>("No skipping confirmation after failure",
                                                     [&]() { verifier.skip_confirmation(); });
         }

         // Malformed key shares are rejected
         {
            Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id, context);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id, context);

            auto share_p = prover.generate_message(this->rng());

            auto truncated = share_p;
            truncated.pop_back();
            result.test_throws<Botan::Decoding_Error>("Truncated share is rejected",
                                                      [&]() { verifier.process_message(truncated, this->rng()); });

            auto compressed_hdr = share_p;
            compressed_hdr[0] = 0x02;
            result.test_throws<Botan::Decoding_Error>("Share without uncompressed header is rejected",
                                                      [&]() { verifier.process_message(compressed_hdr, this->rng()); });

            auto off_curve = share_p;
            off_curve[share_p.size() - 1] ^= 0x01;
            result.test_throws<Botan::Decoding_Error>("Share not on the curve is rejected",
                                                      [&]() { verifier.process_message(off_curve, this->rng()); });

            const auto verifier_msg = verifier.process_message(share_p, this->rng());

            auto bad_verifier_msg = verifier_msg;
            bad_verifier_msg.pop_back();
            result.test_throws<Botan::Decoding_Error>("Truncated verifier message is rejected",
                                                      [&]() { prover.process_message(bad_verifier_msg, this->rng()); });
         }

         // Malformed registration records are rejected
         {
            auto record_bytes = record.serialize();
            record_bytes.pop_back();
            result.test_throws<Botan::Decoding_Error>("Truncated record is rejected", [&]() {
               Botan::SPAKE2p::RegistrationRecord::deserialize(params, record_bytes);
            });
         }

         result.end_timer();
         return result;
      }

      Test::Result test_custom_params() {
         Test::Result result("SPAKE2+ custom system parameters");
         result.start_timer();

         const auto group = Botan::EC_Group::from_name("secp256r1");

         const auto seed = this->rng().random_vec(32);

         const auto h2c_supported = [&]() {
            try {
               Botan::SPAKE2p::SystemParameters::custom(group, seed, "SHA-256");
               return true;
            } catch(Botan::Not_Implemented&) {
               return false;
            }
         }();

         if(!h2c_supported) {
            result.test_note("Skipping test due to missing hash2curve support");
            return result;
         }

         const auto params = Botan::SPAKE2p::SystemParameters::custom(group, seed, "SHA-256");

         const auto rfc_params = Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256();
         result.test_is_true("Custom M differs from RFC 9383 M", params.spake2p_m() != rfc_params.spake2p_m());
         result.test_is_true("Custom N differs from RFC 9383 N", params.spake2p_n() != rfc_params.spake2p_n());

         const auto secret = random_secret(params);
         const auto record = secret.registration_record(this->rng());

         {
            Botan::SPAKE2p::ProverContext prover(params, secret, {}, {}, {});
            Botan::SPAKE2p::VerifierContext verifier(params, record, {}, {}, {});

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            const auto confirm_p = prover.process_message(verifier_msg, this->rng());
            verifier.verify_confirmation(confirm_p);

            result.test_bin_eq("Shared secrets match", prover.shared_secret(), verifier.shared_secret());
         }

         // Peers using different seeds fail during confirmation
         {
            const auto other_seed = this->rng().random_vec(32);
            const auto other_params = Botan::SPAKE2p::SystemParameters::custom(group, other_seed, "SHA-256");

            Botan::SPAKE2p::ProverContext prover(params, secret, {}, {}, {});
            Botan::SPAKE2p::VerifierContext verifier(other_params, record, {}, {}, {});

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            result.test_throws<Botan::Invalid_Authentication_Tag>(
               "Seed mismatch is detected", [&]() { prover.process_message(verifier_msg, this->rng()); });
         }

         result.end_timer();
         return result;
      }

      Botan::SPAKE2p::ProverSecret random_secret(const Botan::SPAKE2p::SystemParameters& params) {
         auto w0 = Botan::EC_Scalar::random(params.group(), this->rng());
         auto w1 = Botan::EC_Scalar::random(params.group(), this->rng());
         return Botan::SPAKE2p::ProverSecret::from_prehashed(std::move(w0), std::move(w1));
      }
};

BOTAN_REGISTER_TEST("pake", "spake2p_rt", SPAKE2p_RT_Tests);

class SPAKE2p_Password_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("SPAKE2+ password registration");
         result.start_timer();

         const auto params = Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256();

         const std::vector<uint8_t> prover_id = {'c', 'l', 'i', 'e', 'n', 't'};
         const std::vector<uint8_t> verifier_id = {'s', 'e', 'r', 'v', 'e', 'r'};
         const auto salt = this->rng().random_vec(16);

         const std::string password = "correct horse battery staple";

         const auto secret =
            Botan::SPAKE2p::ProverSecret::from_password(params, password, prover_id, verifier_id, salt);

         // The record is derived from the same password independently
         const auto record = Botan::SPAKE2p::RegistrationRecord::from_password(
            params, password, prover_id, verifier_id, salt, this->rng());

         {
            Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id);

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            const auto confirm_p = prover.process_message(verifier_msg, this->rng());
            verifier.verify_confirmation(confirm_p);

            result.test_bin_eq("Shared secrets match", prover.shared_secret(), verifier.shared_secret());
         }

         {
            const auto wrong_secret =
               Botan::SPAKE2p::ProverSecret::from_password(params, "hunter2", prover_id, verifier_id, salt);

            Botan::SPAKE2p::ProverContext prover(params, wrong_secret, prover_id, verifier_id);
            Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id);

            const auto verifier_msg = verifier.process_message(prover.generate_message(this->rng()), this->rng());
            result.test_throws<Botan::Invalid_Authentication_Tag>(
               "Wrong password is detected", [&]() { prover.process_message(verifier_msg, this->rng()); });
         }

         result.end_timer();
         return {result};
      }
};

BOTAN_REGISTER_TEST("pake", "spake2p_password", SPAKE2p_Password_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
