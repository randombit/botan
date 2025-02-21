/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PAKE_SPAKE2)
   #include "test_rng.h"
   #include <botan/spake2.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PAKE_SPAKE2)

class SPAKE2_KAT_Tests final : public Text_Based_Test {
   public:
      SPAKE2_KAT_Tests() : Text_Based_Test("pake/spake2.vec", "Group,W,X,Y,Hash,AId,BId,SS") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("SPAKE2 KAT");

         const auto group = Botan::EC_Group::from_name(vars.get_req_str("Group"));
         const std::string hash_fn = vars.get_req_str("Hash");
         const std::vector<uint8_t> a_id = vars.get_req_bin("AId");
         const std::vector<uint8_t> b_id = vars.get_req_bin("BId");
         const std::vector<uint8_t> exp_ss = vars.get_req_bin("SS");

         const Botan::EC_Scalar w(group, vars.get_req_bin("W"));

         Botan::SPAKE2_Parameters params(group, w, a_id, b_id, {}, hash_fn, false);

         Fixed_Output_RNG x_rng(rng());
         x_rng.add_entropy(vars.get_req_bin("X"));
         Botan::SPAKE2_Context a_ctx(Botan::SPAKE2_PeerId::PeerA, params, x_rng);
         const auto a_msg = a_ctx.generate_message();

         Fixed_Output_RNG y_rng(rng());
         y_rng.add_entropy(vars.get_req_bin("Y"));
         Botan::SPAKE2_Context b_ctx(Botan::SPAKE2_PeerId::PeerB, params, y_rng);
         const auto b_msg = b_ctx.generate_message();

         const auto a_ss = a_ctx.process_message(b_msg);
         result.test_eq("Shared secret A matches", a_ss, exp_ss);

         const auto b_ss = b_ctx.process_message(a_msg);
         result.test_eq("Shared secret B matches", b_ss, exp_ss);

         return result;
      }
};

BOTAN_REGISTER_TEST("pake", "spake2_kat", SPAKE2_KAT_Tests);

class SPAKE2_RT_Tests final : public Text_Based_Test {
   public:
      SPAKE2_RT_Tests() : Text_Based_Test("pake/spake2_rt.vec", "Group,Secret,Hash,AId,BId") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("SPAKE2 round trip");

         const auto group = Botan::EC_Group::from_name(vars.get_req_str("Group"));
         const std::string hash_fn = vars.get_req_str("Hash");
         const std::vector<uint8_t> a_id = vars.get_req_bin("AId");
         const std::vector<uint8_t> b_id = vars.get_req_bin("BId");
         const std::string secret = vars.get_req_str("Secret");

         const bool h2c_supported = [&]() {
            try {
               Botan::EC_AffinePoint::hash_to_curve_nu(group, hash_fn, {}, {});
               return true;
            } catch(Botan::Not_Implemented&) {
               return false;
            }
         }();

         // Avoid doing Argon2 twice for each test
         const auto w = Botan::SPAKE2_Parameters::hash_shared_secret(group, secret, a_id, b_id, {});

         for(bool per_user_params : {true, false}) {
            if(per_user_params && !h2c_supported) {
               continue;
            }

            Botan::SPAKE2_Parameters params(group, w, a_id, b_id, {}, hash_fn, per_user_params);

            Botan::SPAKE2_Context a_ctx(Botan::SPAKE2_PeerId::PeerA, params, rng());
            const auto a_msg = a_ctx.generate_message();

            Botan::SPAKE2_Context b_ctx(Botan::SPAKE2_PeerId::PeerB, params, rng());
            const auto b_msg = b_ctx.generate_message();

            const auto a_ss = a_ctx.process_message(b_msg);
            const auto b_ss = b_ctx.process_message(a_msg);

            result.test_eq("Peers produced the same shared secret", a_ss, b_ss);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pake", "spake2_rt", SPAKE2_RT_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests
