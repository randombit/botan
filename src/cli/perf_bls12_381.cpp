/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_BLS12_381)
   #include <botan/bls12_381.h>
   #include <botan/rng.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_BLS12_381)

namespace {

Botan::BLS12_381::Scalar random_bls_scalar(Botan::RandomNumberGenerator& rng) {
   std::array<uint8_t, 64> buf{};
   rng.randomize(buf);
   return Botan::BLS12_381::Scalar::from_bytes_wide(buf);
}

class PerfTest_Bls12_381 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto run = config.runtime();
         auto& rng = config.rng();

         using namespace Botan::BLS12_381;

         const auto g1 = G1Projective::generator();
         const auto g2 = G2Projective::generator();

         auto g1_mul_timer = config.make_timer("BLS12-381 G1 mul");
         while(g1_mul_timer->under(run)) {
            const auto k = random_bls_scalar(rng);
            g1_mul_timer->run([&]() { return g1.mul(k); });
         }
         config.record_result(*g1_mul_timer);

         auto g2_mul_timer = config.make_timer("BLS12-381 G2 mul");
         while(g2_mul_timer->under(run)) {
            const auto k = random_bls_scalar(rng);
            g2_mul_timer->run([&]() { return g2.mul(k); });
         }
         config.record_result(*g2_mul_timer);

         auto g1_mul2_timer = config.make_timer("BLS12-381 G1 mul2");
         auto g1_mul2_vt_timer = config.make_timer("BLS12-381 G1 mul2_vartime");
         while(g1_mul2_timer->under(run)) {
            const auto p = g1.mul(random_bls_scalar(rng));
            const auto q = g1.mul(random_bls_scalar(rng));
            const auto a = random_bls_scalar(rng);
            const auto b = random_bls_scalar(rng);
            g1_mul2_timer->run([&]() { return G1Projective::mul2(p, a, q, b); });
            g1_mul2_vt_timer->run([&]() { return G1Projective::mul2_vartime(p, a, q, b); });
         }
         config.record_result(*g1_mul2_timer);
         config.record_result(*g1_mul2_vt_timer);

         auto g1_deser_timer = config.make_timer("BLS12-381 G1 deserialize");
         while(g1_deser_timer->under(run)) {
            const auto bytes = g1.mul(random_bls_scalar(rng)).to_affine().serialize();
            g1_deser_timer->run([&]() { return G1Affine::deserialize(bytes); });
         }
         config.record_result(*g1_deser_timer);

         auto g2_deser_timer = config.make_timer("BLS12-381 G2 deserialize");
         while(g2_deser_timer->under(run)) {
            const auto bytes = g2.mul(random_bls_scalar(rng)).to_affine().serialize();
            g2_deser_timer->run([&]() { return G2Affine::deserialize(bytes); });
         }
         config.record_result(*g2_deser_timer);

         auto g1_h2c_timer = config.make_timer("BLS12-381 G1 hash to curve");
         while(g1_h2c_timer->under(run)) {
            std::array<uint8_t, 32> input{};
            rng.randomize(input);
            const auto dst = std::span{input}.first(16);
            g1_h2c_timer->run([&]() { return G1Projective::hash_to_curve_ro(input, dst); });
         }
         config.record_result(*g1_h2c_timer);

         auto g2_h2c_timer = config.make_timer("BLS12-381 G2 hash to curve");
         while(g2_h2c_timer->under(run)) {
            std::array<uint8_t, 32> input{};
            rng.randomize(input);
            const auto dst = std::span{input}.first(16);
            g2_h2c_timer->run([&]() { return G2Projective::hash_to_curve_ro(input, dst); });
         }
         config.record_result(*g2_h2c_timer);

         auto pairing_timer = config.make_timer("BLS12-381 pairing");
         while(pairing_timer->under(run)) {
            const auto a = g1.mul(random_bls_scalar(rng)).to_affine();
            const auto b = g2.mul(random_bls_scalar(rng)).to_affine();
            pairing_timer->run([&]() { return Gt::pairing(a, b); });
         }
         config.record_result(*pairing_timer);

         for(const size_t n : {2, 8}) {
            std::vector<G1Projective> ps_proj;
            std::vector<G2Projective> qs_proj;
            for(size_t i = 0; i != n; ++i) {
               ps_proj.push_back(g1.mul(random_bls_scalar(rng)));
               qs_proj.push_back(g2.mul(random_bls_scalar(rng)));
            }
            const auto ps = G1Projective::to_affine_batch(ps_proj);
            const auto qs = G2Projective::to_affine_batch(qs_proj);

            auto mp_timer = config.make_timer("BLS12-381 multi-pairing (" + std::to_string(n) + ")");
            while(mp_timer->under(run)) {
               mp_timer->run([&]() { return Gt::multi_pairing(ps, qs); });
            }
            config.record_result(*mp_timer);
         }

         for(const size_t n : {4, 32, 256}) {
            std::vector<G1Projective> proj;
            proj.reserve(n);
            for(size_t i = 0; i != n; ++i) {
               proj.push_back(g1.mul(random_bls_scalar(rng)));
            }
            const auto points = G1Projective::to_affine_batch(proj);

            auto msm_timer = config.make_timer("BLS12-381 G1 MSM " + std::to_string(n) + " (per point)", n);
            while(msm_timer->under(run)) {
               std::vector<Scalar> scalars;
               scalars.reserve(n);
               for(size_t i = 0; i != n; ++i) {
                  scalars.push_back(random_bls_scalar(rng));
               }
               msm_timer->run([&]() { return G1Projective::msm_vartime(points, scalars); });
            }
            config.record_result(*msm_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("bls12_381", PerfTest_Bls12_381);

}  // namespace

#endif

}  // namespace Botan_CLI
