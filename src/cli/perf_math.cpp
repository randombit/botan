/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"

#if defined(BOTAN_HAS_BIGINT)
   #include <botan/bigint.h>
   #include <botan/internal/divide.h>
#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
   #include <botan/reducer.h>
   #include <botan/internal/primality.h>
#endif

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_BIGINT)

class PerfTest_MpMul final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         std::chrono::milliseconds runtime_per_size = config.runtime();

         for(size_t bits : {256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096}) {
            auto mul_timer = config.make_timer("BigInt mul " + std::to_string(bits));
            auto sqr_timer = config.make_timer("BigInt sqr " + std::to_string(bits));

            const Botan::BigInt y(config.rng(), bits);
            Botan::secure_vector<Botan::word> ws;

            while(mul_timer->under(runtime_per_size)) {
               Botan::BigInt x(config.rng(), bits);

               sqr_timer->start();
               x.square(ws);
               sqr_timer->stop();

               x.mask_bits(bits);

               mul_timer->start();
               x.mul(y, ws);
               mul_timer->stop();
            }

            config.record_result(*mul_timer);
            config.record_result(*sqr_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("mp_mul", PerfTest_MpMul);

class PerfTest_MpDiv final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         std::chrono::milliseconds runtime_per_size = config.runtime();

         for(size_t n_bits : {256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096}) {
            const size_t q_bits = n_bits / 2;
            const std::string bit_descr = std::to_string(n_bits) + "/" + std::to_string(q_bits);

            auto div_timer = config.make_timer("BigInt div " + bit_descr);
            auto ct_div_timer = config.make_timer("BigInt ct_div " + bit_descr);

            Botan::BigInt y;
            Botan::BigInt x;
            Botan::secure_vector<Botan::word> ws;

            Botan::BigInt q1, r1, q2, r2;

            while(ct_div_timer->under(runtime_per_size)) {
               x.randomize(config.rng(), n_bits);
               y.randomize(config.rng(), q_bits);

               div_timer->start();
               Botan::vartime_divide(x, y, q1, r1);
               div_timer->stop();

               ct_div_timer->start();
               Botan::ct_divide(x, y, q2, r2);
               ct_div_timer->stop();

               BOTAN_ASSERT_EQUAL(q1, q2, "Quotient ok");
               BOTAN_ASSERT_EQUAL(r1, r2, "Remainder ok");
            }

            config.record_result(*div_timer);
            config.record_result(*ct_div_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("mp_div", PerfTest_MpDiv);

class PerfTest_MpDiv10 final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         std::chrono::milliseconds runtime_per_size = config.runtime();

         for(size_t n_bits : {256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096}) {
            const std::string bit_descr = std::to_string(n_bits) + "/10";

            auto div_timer = config.make_timer("BigInt div " + bit_descr);
            auto ct_div_timer = config.make_timer("BigInt ct_div " + bit_descr);

            Botan::BigInt x;
            Botan::secure_vector<Botan::word> ws;

            const auto ten = Botan::BigInt::from_word(10);
            Botan::BigInt q1, r1, q2;
            Botan::word r2;

            while(ct_div_timer->under(runtime_per_size)) {
               x.randomize(config.rng(), n_bits);

               div_timer->start();
               Botan::vartime_divide(x, ten, q1, r1);
               div_timer->stop();

               ct_div_timer->start();
               Botan::ct_divide_word(x, 10, q2, r2);
               ct_div_timer->stop();

               BOTAN_ASSERT_EQUAL(q1, q2, "Quotient ok");
               BOTAN_ASSERT_EQUAL(r1, r2, "Remainder ok");
            }

            config.record_result(*div_timer);
            config.record_result(*ct_div_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("mp_div10", PerfTest_MpDiv10);

#endif

#if defined(BOTAN_HAS_NUMBERTHEORY)

class PerfTest_BnRedc final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto runtime = config.runtime();

         for(size_t bitsize : {512, 1024, 2048, 4096}) {
            Botan::BigInt p(config.rng(), bitsize);

            std::string bit_str = std::to_string(bitsize) + " bit ";
            auto barrett_setup_pub_timer = config.make_timer(bit_str + "Barrett setup public");
            auto barrett_setup_sec_timer = config.make_timer(bit_str + "Barrett setup secret");

            while(barrett_setup_sec_timer->under(runtime)) {
               barrett_setup_sec_timer->run([&]() { Botan::Modular_Reducer::for_secret_modulus(p); });
               barrett_setup_pub_timer->run([&]() { Botan::Modular_Reducer::for_public_modulus(p); });
            }

            config.record_result(*barrett_setup_pub_timer);
            config.record_result(*barrett_setup_sec_timer);

            auto mod_p = Botan::Modular_Reducer::for_public_modulus(p);

            auto barrett_timer = config.make_timer(bit_str + "Barrett redc");
            auto knuth_timer = config.make_timer(bit_str + "Knuth redc");
            auto ct_modulo_timer = config.make_timer(bit_str + "ct_modulo");

            while(ct_modulo_timer->under(runtime)) {
               const Botan::BigInt x(config.rng(), p.bits() * 2 - 1);

               const Botan::BigInt r1 = barrett_timer->run([&] { return mod_p.reduce(x); });
               const Botan::BigInt r2 = knuth_timer->run([&] { return x % p; });
               const Botan::BigInt r3 = ct_modulo_timer->run([&] { return Botan::ct_modulo(x, p); });

               BOTAN_ASSERT(r1 == r2, "Computed different results");
               BOTAN_ASSERT(r1 == r3, "Computed different results");
            }

            config.record_result(*barrett_timer);
            config.record_result(*knuth_timer);
            config.record_result(*ct_modulo_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("bn_redc", PerfTest_BnRedc);

class PerfTest_InvMod final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto runtime = config.runtime();

         for(size_t bits : {256, 384, 512, 1024, 2048}) {
            const std::string bit_str = std::to_string(bits);

            auto timer = config.make_timer("inverse_mod-" + bit_str);
            auto gcd_timer = config.make_timer("gcd-" + bit_str);

            while(timer->under(runtime) && gcd_timer->under(runtime)) {
               const Botan::BigInt x(config.rng(), bits - 1);
               Botan::BigInt mod(config.rng(), bits);

               const Botan::BigInt x_inv = timer->run([&] { return Botan::inverse_mod(x, mod); });

               const Botan::BigInt g = gcd_timer->run([&] { return gcd(x, mod); });

               if(x_inv == 0) {
                  BOTAN_ASSERT(g != 1, "Inversion only fails if gcd(x, mod) > 1");
               } else {
                  BOTAN_ASSERT(g == 1, "Inversion succeeds only if gcd != 1");
                  const Botan::BigInt check = (x_inv * x) % mod;
                  BOTAN_ASSERT_EQUAL(check, 1, "Const time inversion correct");
               }
            }

            config.record_result(*timer);
            config.record_result(*gcd_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("inverse_mod", PerfTest_InvMod);

class PerfTest_IsPrime final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto runtime = config.runtime();

         for(size_t bits : {256, 512, 1024}) {
            auto mr_timer = config.make_timer("Miller-Rabin-" + std::to_string(bits));
            auto bpsw_timer = config.make_timer("Bailie-PSW-" + std::to_string(bits));
            auto lucas_timer = config.make_timer("Lucas-" + std::to_string(bits));

            Botan::BigInt n = Botan::random_prime(config.rng(), bits);

            while(lucas_timer->under(runtime)) {
               auto mod_n = Botan::Modular_Reducer::for_public_modulus(n);

               mr_timer->run([&]() { return Botan::is_miller_rabin_probable_prime(n, mod_n, config.rng(), 2); });

               bpsw_timer->run([&]() { return Botan::is_bailie_psw_probable_prime(n, mod_n); });

               lucas_timer->run([&]() { return Botan::is_lucas_probable_prime(n, mod_n); });

               n += 2;
            }

            config.record_result(*mr_timer);
            config.record_result(*bpsw_timer);
            config.record_result(*lucas_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("primality_test", PerfTest_IsPrime);

class PerfTest_RandomPrime final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         const auto coprime = Botan::BigInt::from_word(0x10001);
         const auto runtime = config.runtime();

         auto& rng = config.rng();

         for(size_t bits : {256, 384, 512, 768, 1024, 1536}) {
            auto genprime_timer = config.make_timer("random_prime " + std::to_string(bits));
            auto gensafe_timer = config.make_timer("random_safe_prime " + std::to_string(bits));
            auto is_prime_timer = config.make_timer("is_prime " + std::to_string(bits));

            while(gensafe_timer->under(runtime)) {
               const Botan::BigInt p = genprime_timer->run([&] { return Botan::random_prime(rng, bits, coprime); });

               if(!is_prime_timer->run([&] { return Botan::is_prime(p, rng, 64, true); })) {
                  config.error_output() << "Generated prime " << p << " which failed a primality test";
               }

               const Botan::BigInt sg = gensafe_timer->run([&] { return Botan::random_safe_prime(rng, bits); });

               if(!is_prime_timer->run([&] { return Botan::is_prime(sg, rng, 64, true); })) {
                  config.error_output() << "Generated safe prime " << sg << " which failed a primality test";
               }

               if(!is_prime_timer->run([&] { return Botan::is_prime(sg / 2, rng, 64, true); })) {
                  config.error_output() << "Generated prime " << sg / 2 << " which failed a primality test";
               }

               // Now test p+2, p+4, ... which may or may not be prime
               for(size_t i = 2; i <= 64; i += 2) {
                  is_prime_timer->run([&]() { Botan::is_prime(p + i, rng, 64, true); });
               }
            }

            config.record_result(*genprime_timer);
            config.record_result(*gensafe_timer);
            config.record_result(*is_prime_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("random_prime", PerfTest_RandomPrime);

#endif

#if defined(BOTAN_HAS_DL_GROUP)

class PerfTest_ModExp final : public PerfTest {
   public:
      void go(const PerfConfig& config) override {
         for(size_t group_bits : {1024, 1536, 2048, 3072, 4096, 6144, 8192}) {
            const std::string group_name = "modp/ietf/" + std::to_string(group_bits);
            auto group = Botan::DL_Group::from_name(group_name);

            const size_t e_bits = group.exponent_bits();
            const size_t f_bits = group_bits - 1;

            const Botan::BigInt random_e(config.rng(), e_bits);
            const Botan::BigInt random_f(config.rng(), f_bits);

            auto e_timer = config.make_timer(group_name + " short exp");
            auto f_timer = config.make_timer(group_name + "  full exp");

            while(f_timer->under(config.runtime())) {
               e_timer->run([&]() { group.power_g_p(random_e, e_bits); });
               f_timer->run([&]() { group.power_g_p(random_f, f_bits); });
            }

            config.record_result(*e_timer);
            config.record_result(*f_timer);
         }
      }
};

BOTAN_REGISTER_PERF_TEST("modexp", PerfTest_ModExp);

#endif

}  // namespace Botan_CLI
