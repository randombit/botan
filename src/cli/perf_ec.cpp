/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_ECC_GROUP)

class PerfTest_EllipticCurve final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto run = config.runtime();
         auto& rng = config.rng();

         for(const auto& group_name : config.ecc_groups()) {
            auto init_timer = config.make_timer(group_name + " initialization");

            while(init_timer->under(run)) {
               Botan::EC_Group::clear_registered_curve_data();
               init_timer->run([&]() { Botan::EC_Group::from_name(group_name); });
            }

            config.record_result(*init_timer);

            const auto group = Botan::EC_Group::from_name(group_name);

            auto bp_timer = config.make_timer(group_name + " base point mul");
            auto vp_timer = config.make_timer(group_name + " variable point mul");
            auto add_timer = config.make_timer(group_name + " point addition");
            auto der_uc_timer = config.make_timer(group_name + " point deserialize (uncompressed)");
            auto der_c_timer = config.make_timer(group_name + " point deserialize (compressed)");
            auto mul2_setup_timer = config.make_timer(group_name + " mul2 setup");
            auto mul2_timer = config.make_timer(group_name + " mul2");
            auto scalar_inv_timer = config.make_timer(group_name + " scalar inversion");
            auto scalar_inv_vt_timer = config.make_timer(group_name + " scalar inversion vartime");
            auto h2c_nu_timer = config.make_timer(group_name + " hash to curve (NU)");
            auto h2c_ro_timer = config.make_timer(group_name + " hash to curve (RO)");

            auto g = Botan::EC_AffinePoint::generator(group);

            const bool h2c_supported = [&]() {
               try {
                  Botan::EC_AffinePoint::hash_to_curve_nu(group, "SHA-256", {}, {});
               } catch(Botan::Not_Implemented&) {
                  return false;
               }
               return true;
            }();

            while(bp_timer->under(run) && vp_timer->under(run)) {
               const auto k = Botan::EC_Scalar::random(group, rng);
               const auto k2 = Botan::EC_Scalar::random(group, rng);
               const auto r1 = bp_timer->run([&]() { return Botan::EC_AffinePoint::g_mul(k, rng); });
               const auto r2 = vp_timer->run([&]() { return g.mul(k, rng); });

               const auto r1_bytes = r1.serialize_uncompressed();
               const auto r2_bytes = r2.serialize_uncompressed();
               BOTAN_ASSERT_EQUAL(r1_bytes, r2_bytes, "Same result for multiplication");

               add_timer->run([&]() { r1.add(r2); });

               der_uc_timer->run([&]() { Botan::EC_AffinePoint::deserialize(group, r1_bytes); });

               const auto r1_cbytes = r1.serialize_compressed();
               der_c_timer->run([&]() { Botan::EC_AffinePoint::deserialize(group, r1_cbytes); });

               auto mul2 = mul2_setup_timer->run([&]() { return Botan::EC_Group::Mul2Table(r1); });

               auto pt = mul2_timer->run([&]() { return mul2.mul2_vartime(k, k2); });

               if(h2c_supported) {
                  h2c_nu_timer->run([&]() { Botan::EC_AffinePoint::hash_to_curve_nu(group, "SHA-256", r1_bytes, {}); });
                  h2c_ro_timer->run([&]() { Botan::EC_AffinePoint::hash_to_curve_ro(group, "SHA-256", r1_bytes, {}); });
               }
            }

            while(scalar_inv_timer->under(config.runtime())) {
               const auto k = Botan::EC_Scalar::random(group, rng);
               auto k_vt_inv = scalar_inv_vt_timer->run([&]() { return k.invert_vartime(); });
               auto k_inv = scalar_inv_timer->run([&]() { return k.invert(); });
               BOTAN_ASSERT_EQUAL(k_inv, k_vt_inv, "Same result for inversion");
            }

            config.record_result(*add_timer);
            config.record_result(*bp_timer);
            config.record_result(*vp_timer);
            config.record_result(*mul2_setup_timer);
            config.record_result(*mul2_timer);
            config.record_result(*scalar_inv_timer);
            config.record_result(*scalar_inv_vt_timer);
            config.record_result(*der_uc_timer);
            config.record_result(*der_c_timer);

            if(h2c_supported) {
               config.record_result(*h2c_nu_timer);
               config.record_result(*h2c_ro_timer);
            }
         }
      }
};

BOTAN_REGISTER_PERF_TEST("ecc", PerfTest_EllipticCurve);

#endif

}  // namespace Botan_CLI
