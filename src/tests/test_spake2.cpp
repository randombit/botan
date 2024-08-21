/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)
   #include "test_rng.h"
   #include <botan/hash.h>
   #include <botan/spake2p.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PAKE_SPAKE2PLUS)

class SPAKE2p_KAT_Tests final : public Text_Based_Test {
   public:
      SPAKE2p_KAT_Tests() : Text_Based_Test("pake/spake2.vec", "Group,W,X,Y,Hash,AId,BId,SS") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("SPAKE2+ KAT");

         const auto group = Botan::EC_Group::from_name(vars.get_req_str("Group"));
         const std::string hash_fn = vars.get_req_str("Hash");
         const std::vector<uint8_t> a_id = vars.get_req_bin("AId");
         const std::vector<uint8_t> b_id = vars.get_req_bin("BId");
         const std::vector<uint8_t> exp_ss = vars.get_req_bin("SS");

         const Botan::EC_Scalar w(group, vars.get_req_bin("W"));

         Botan::SPAKE2p::Parameters params(group, w, a_id, b_id, {}, hash_fn, false);

         Fixed_Output_RNG x_rng(rng());
         x_rng.add_entropy(vars.get_req_bin("X"));
         Botan::SPAKE2p::Context a_ctx(Botan::SPAKE2p::PeerId::PeerA, params, x_rng);
         const auto a_msg = a_ctx.generate_message();

         Fixed_Output_RNG y_rng(rng());
         y_rng.add_entropy(vars.get_req_bin("Y"));
         Botan::SPAKE2p::Context b_ctx(Botan::SPAKE2p::PeerId::PeerB, params, y_rng);
         const auto b_msg = b_ctx.generate_message();

         const auto a_ss = a_ctx.process_message(b_msg);
         result.test_eq("Shared secret A matches", a_ss, exp_ss);

         const auto b_ss = b_ctx.process_message(a_msg);
         result.test_eq("Shared secret B matches", b_ss, exp_ss);

         return result;
      }
};

BOTAN_REGISTER_TEST("pake", "spake2_kat", SPAKE2p_KAT_Tests);

class SPAKE2p_RT_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         const std::vector<std::string> groups = {"secp256r1", "secp384r1", "secp521r1"};
         const std::vector<std::string> hash_fns = {"SHA-256", "SHA-384", "SHA-512"};

         const std::vector<uint8_t> a_id = {0xF0, 0x0F, 0xEE};
         const std::vector<uint8_t> b_id = {0xAB, 0xE0};
         const std::string secret = "squirrel";
         const auto context = rng().random_vec(32);
         const auto bad_context = rng().random_vec(32);

         for(const auto& group_name : groups) {
            Test::Result result("SPAKE2 round trip " + group_name);
            result.start_timer();

            if(!Botan::EC_Group::supports_named_group(group_name)) {
               continue;
            }

            const auto group = Botan::EC_Group::from_name(group_name);

            for(const auto& hash_fn : hash_fns) {
               const bool h2c_supported = [&]() {
                  try {
                     Botan::EC_AffinePoint::hash_to_curve_nu(group, hash_fn, {}, "");
                     return true;
                  } catch(Botan::Not_Implemented&) {
                     return false;
                  }
               }();

               const auto w = test_hash_shared_secret(group, secret, a_id, b_id, context);
               const auto bad_w = w + Botan::EC_Scalar::one(group);

               for(bool per_user_params : {true, false}) {
                  if(per_user_params && !h2c_supported) {
                     continue;
                  }

                  result.confirm(
                     "Same shared key in normal operation",
                     spake2_test_run(rng(), group, hash_fn, per_user_params, a_id, w, context, b_id, w, context));

                  // clang-format off
                  result.confirm("Different shared key if secret is different",
                                 !spake2_test_run(rng(), group, hash_fn, per_user_params, a_id, w, context, b_id, bad_w, context));

                  result.confirm("Different shared key if context is different",
                                 !spake2_test_run(rng(), group, hash_fn, per_user_params, a_id, w, context, b_id, w, bad_context));
                  // clang-format on
               }
            }

            result.end_timer();
            results.push_back(result);
         }

         return results;
      }

   private:
      static bool spake2_test_run(Botan::RandomNumberGenerator& rng,
                                  const Botan::EC_Group& group,
                                  std::string_view hash_fn,
                                  bool per_user_params,
                                  std::span<const uint8_t> a_id,
                                  const Botan::EC_Scalar& a_secret,
                                  std::span<const uint8_t> a_context,
                                  std::span<const uint8_t> b_id,
                                  const Botan::EC_Scalar& b_secret,
                                  std::span<const uint8_t> b_context) {
         Botan::SPAKE2p::Parameters a_params(group, a_secret, a_id, b_id, a_context, hash_fn, per_user_params);
         Botan::SPAKE2p::Context a_ctx(Botan::SPAKE2p::PeerId::PeerA, a_params, rng);
         const auto a_msg = a_ctx.generate_message();

         Botan::SPAKE2p::Parameters b_params(group, b_secret, a_id, b_id, b_context, hash_fn, per_user_params);
         Botan::SPAKE2p::Context b_ctx(Botan::SPAKE2p::PeerId::PeerB, b_params, rng);
         const auto b_msg = b_ctx.generate_message();

         const auto a_ss = a_ctx.process_message(b_msg);
         const auto b_ss = b_ctx.process_message(a_msg);

         return (a_ss == b_ss);
      }

      static Botan::EC_Scalar test_hash_shared_secret(const Botan::EC_Group& group,
                                                      std::string_view secret,
                                                      std::span<const uint8_t> a_id,
                                                      std::span<const uint8_t> b_id,
                                                      std::span<const uint8_t> context) {
         /***
         * WARNING do not copy this into production code
         *
         * This is just a standin for SPAKE2p::Parameters::hash_shared_secret that is
         * fast, to avoid repeated Argon2 calculations in the test
         ***/

         const std::string_view hash_fn = "SHA-512";

         auto hash = Botan::HashFunction::create_or_throw(hash_fn);

         auto a_h = hash->process(a_id);
         auto b_h = hash->process(b_id);
         auto c_h = hash->process(context);

         hash->update(a_h);
         hash->update(b_h);
         hash->update(c_h);
         hash->update(secret);

         return Botan::EC_Scalar::hash(group, hash_fn, hash->final(), {});
      }
};

BOTAN_REGISTER_TEST("pake", "spake2p_rt", SPAKE2p_RT_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests
