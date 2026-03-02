/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/assert.h>
   #include <botan/ec_group.h>
   #include <botan/rng.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_ECC_GROUP)

class PerfTest_EllipticCurve_Mul final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto run = config.runtime();
         auto& rng = config.rng();

         for(const auto& group_name : config.ecc_groups()) {
            const auto group = Botan::EC_Group::from_name(group_name);

            auto bp_timer = config.make_timer(group_name + " blinded base point mul");
            auto bp_nb_timer = config.make_timer(group_name + " unblinded base point mul");

            auto vp_timer = config.make_timer(group_name + " blinded variable point mul");
            auto vp_nb_timer = config.make_timer(group_name + " unblinded variable point mul");

            auto g = Botan::EC_AffinePoint::generator(group);

            Botan::Null_RNG null_rng;

            while(bp_timer->under(run) && vp_timer->under(run)) {
               const auto k = Botan::EC_Scalar::random(group, rng);

               const auto r1 = bp_timer->run([&]() { return Botan::EC_AffinePoint::g_mul(k, rng); });
               const auto r2 = vp_timer->run([&]() { return g.mul(k, rng); });
               const auto r3 = bp_nb_timer->run([&]() { return Botan::EC_AffinePoint::g_mul(k, null_rng); });
               const auto r4 = vp_nb_timer->run([&]() { return g.mul(k, null_rng); });

               BOTAN_ASSERT_NOMSG(r1 == r2);
               BOTAN_ASSERT_NOMSG(r1 == r3);
               BOTAN_ASSERT_NOMSG(r1 == r4);
            }

            config.record_result(*bp_timer);
            config.record_result(*bp_nb_timer);
            config.record_result(*vp_timer);
            config.record_result(*vp_nb_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("ecc_mul", PerfTest_EllipticCurve_Mul);

class PerfTest_EllipticCurve_Mul2 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto run = config.runtime();
         auto& rng = config.rng();

         for(const auto& group_name : config.ecc_groups()) {
            const auto group = Botan::EC_Group::from_name(group_name);

            auto mul2_setup_timer = config.make_timer(group_name + " mul2_vartime setup");
            auto mul2_vt_timer = config.make_timer(group_name + " mul2_vartime");
            auto mul2_ct_timer = config.make_timer(group_name + " blinded mul2");
            auto mul2_ct_nb_timer = config.make_timer(group_name + " unblinded mul2");

            Botan::Null_RNG null_rng;

            auto g = Botan::EC_AffinePoint::generator(group);

            while(mul2_setup_timer->under(run) && mul2_ct_timer->under(run)) {
               const auto k = Botan::EC_Scalar::random(group, rng);
               const auto k2 = Botan::EC_Scalar::random(group, rng);

               const auto y = Botan::EC_AffinePoint::g_mul(Botan::EC_Scalar::random(group, rng), rng);

               auto mul2 = mul2_setup_timer->run([&]() { return Botan::EC_Group::Mul2Table(y); });

               auto pt = mul2_vt_timer->run([&]() { return mul2.mul2_vartime(k, k2); });

               auto pt2 = mul2_ct_timer->run([&]() { return Botan::EC_AffinePoint::mul_px_qy(g, k, y, k2, rng); });

               auto pt3 =
                  mul2_ct_nb_timer->run([&]() { return Botan::EC_AffinePoint::mul_px_qy(g, k, y, k2, null_rng); });

               BOTAN_ASSERT_NOMSG(pt == pt2);
               BOTAN_ASSERT_NOMSG(pt == pt3);
            }

            config.record_result(*mul2_setup_timer);
            config.record_result(*mul2_vt_timer);
            config.record_result(*mul2_ct_timer);
            config.record_result(*mul2_ct_nb_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("ecc_mul2", PerfTest_EllipticCurve_Mul2);

class PerfTest_EllipticCurve_H2C final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto run = config.runtime();
         auto& rng = config.rng();

         for(const auto& group_name : config.ecc_groups()) {
            const auto group = Botan::EC_Group::from_name(group_name);

            const bool h2c_supported = [&]() {
               try {
                  Botan::EC_AffinePoint::hash_to_curve_nu(group, "SHA-256", {}, "");
               } catch(Botan::Not_Implemented&) {
                  return false;
               }
               return true;
            }();

            if(!h2c_supported) {
               continue;
            }

            auto h2c_nu_timer = config.make_timer(group_name + " hash to curve (NU)");
            auto h2c_ro_timer = config.make_timer(group_name + " hash to curve (RO)");

            std::vector<uint8_t> input(32);

            while(h2c_ro_timer->under(run)) {
               rng.randomize(input);
               h2c_nu_timer->run([&]() { Botan::EC_AffinePoint::hash_to_curve_nu(group, "SHA-256", input, "domain"); });
               h2c_ro_timer->run([&]() { Botan::EC_AffinePoint::hash_to_curve_ro(group, "SHA-256", input, "domain"); });
            }

            config.record_result(*h2c_nu_timer);
            config.record_result(*h2c_ro_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("ecc_h2c", PerfTest_EllipticCurve_H2C);

class PerfTest_EllipticCurve_Misc final : public PerfTest {
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

            auto add_timer = config.make_timer(group_name + " point addition");
            auto der_uc_timer = config.make_timer(group_name + " point deserialize (uncompressed)");
            auto der_c_timer = config.make_timer(group_name + " point deserialize (compressed)");
            auto scalar_inv_timer = config.make_timer(group_name + " scalar inversion");
            auto scalar_inv_vt_timer = config.make_timer(group_name + " scalar inversion vartime");

            while(add_timer->under(run) && der_c_timer->under(run) && scalar_inv_timer->under(run)) {
               const auto r1 = Botan::EC_AffinePoint::g_mul(Botan::EC_Scalar::random(group, rng), rng);
               const auto r2 = Botan::EC_AffinePoint::g_mul(Botan::EC_Scalar::random(group, rng), rng);

               const auto r1_bytes = r1.serialize_uncompressed();
               const auto r2_bytes = r2.serialize_uncompressed();

               add_timer->run([&]() { r1.add(r2); });

               der_uc_timer->run([&]() { Botan::EC_AffinePoint::deserialize(group, r1_bytes); });
               der_uc_timer->run([&]() { Botan::EC_AffinePoint::deserialize(group, r2_bytes); });

               const auto r1_cbytes = r1.serialize_compressed();
               const auto r2_cbytes = r2.serialize_compressed();
               der_c_timer->run([&]() { Botan::EC_AffinePoint::deserialize(group, r1_cbytes); });
               der_c_timer->run([&]() { Botan::EC_AffinePoint::deserialize(group, r2_cbytes); });

               const auto k = Botan::EC_Scalar::random(group, rng);
               auto k_vt_inv = scalar_inv_vt_timer->run([&]() { return k.invert_vartime(); });
               auto k_inv = scalar_inv_timer->run([&]() { return k.invert(); });
               BOTAN_ASSERT_EQUAL(k_inv, k_vt_inv, "Same result for inversion");
            }

            config.record_result(*add_timer);
            config.record_result(*scalar_inv_timer);
            config.record_result(*scalar_inv_vt_timer);
            config.record_result(*der_uc_timer);
            config.record_result(*der_c_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("ecc_misc", PerfTest_EllipticCurve_Misc);

#endif

}  // namespace Botan_CLI
