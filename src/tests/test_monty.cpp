/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
   #include <botan/rng.h>
   #include <botan/internal/barrett.h>
   #include <botan/internal/monty.h>
   #include <botan/internal/monty_exp.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_NUMBERTHEORY)

class Montgomery_Integer_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         auto rng = Test::new_rng(__func__);

         std::vector<Test::Result> results;

         Botan::secure_vector<Botan::word> ws;

         for(size_t i = 0; i != 100; ++i) {
            Test::Result result("Montgomery_Int");

            const size_t p_bits = (3 * i + 5);
            const auto p = Botan::random_prime(*rng, p_bits);

            const Botan::Montgomery_Params params(p);

            const auto x = Botan::BigInt::random_integer(*rng, 1, p);
            const auto y = Botan::BigInt::random_integer(*rng, 1, p);

            const auto monty_x = Botan::Montgomery_Int(params, x, true);
            const auto monty_y = Botan::Montgomery_Int(params, y, true);

            result.test_bn_eq("Montgomery addition", (monty_x + monty_y).value(), (x + y) % p);
            result.test_bn_eq("Montgomery subtraction", (monty_x - monty_y).value(), (x - y) % p);
            result.test_bn_eq("Montgomery multiplication", (monty_x.mul(monty_y, ws)).value(), (x * y) % p);

            result.test_bn_eq("Montgomery square x", (monty_x.square(ws)).value(), (x * x) % p);
            result.test_bn_eq("Montgomery square y", (monty_y.square(ws)).value(), (y * y) % p);

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("math", "monty_int", Montgomery_Integer_Tests);

class Montgomery_Exponentiation_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         auto rng = Test::new_rng(__func__);

         Test::Result result("Montgomery exponentiation");

         /*
         * The sizes just below and above multiples of 416 bits exercise each of the
         * vector widths used by the AVX-512 implementation, and the sizes just past
         * its upper limit (4158 bits) fall back to the generic code.
         */
         const std::vector<size_t> p_bits_to_test = {64,   128,  300,  414,  415,  416,  512,  830,  831,  1024, 1025,
                                                     1100, 1246, 1247, 1536, 1662, 1663, 2048, 2078, 2079, 2494, 2495,
                                                     2910, 2911, 3072, 3326, 3327, 3328, 4096, 4158, 4159};

         for(const size_t p_bits : p_bits_to_test) {
            std::vector<Botan::BigInt> moduli;

            // The structured moduli stress the carry handling, but the large sizes are expensive
            if(p_bits <= 2048 || Test::run_long_tests()) {
               moduli.push_back(Botan::BigInt::power_of_2(p_bits) - 1);
            }
            if(Test::run_long_tests()) {
               moduli.push_back(Botan::BigInt::power_of_2(p_bits - 1) + 1);
            }

            Botan::BigInt random_p(*rng, p_bits);
            random_p.set_bit(p_bits - 1);
            random_p.set_bit(0);
            moduli.push_back(random_p);

            for(const auto& p : moduli) {
               test_modulus(result, *rng, p);
            }
         }

         // Windows other than the default used by the library
         const auto p = Botan::random_prime(*rng, 1024);
         const Botan::Montgomery_Params params(p);
         const auto mod_p = Botan::Barrett_Reduction::for_public_modulus(p);
         const Botan::BigInt g(*rng, 1023);
         const Botan::BigInt k(*rng, 1000);
         const auto expected = ref_powmod(g, k, mod_p);

         for(const size_t window : {1, 2, 3, 5, 6, 7}) {
            const auto precomp = Botan::monty_precompute(params, g, window, true);
            result.test_bn_eq("const time window " + std::to_string(window),
                              Botan::monty_execute(*precomp, k, 1024).value(),
                              expected);
            result.test_bn_eq(
               "vartime window " + std::to_string(window), Botan::monty_execute_vartime(*precomp, k).value(), expected);
         }

         return {result};
      }

   private:
      static Botan::BigInt ref_powmod(const Botan::BigInt& base,
                                      const Botan::BigInt& exp,
                                      const Botan::Barrett_Reduction& mod_p) {
         const Botan::BigInt b = mod_p.reduce(base);
         Botan::BigInt r = Botan::BigInt::one();
         for(size_t i = exp.bits(); i > 0; --i) {
            r = mod_p.square(r);
            if(exp.get_bit(i - 1)) {
               r = mod_p.multiply(r, b);
            }
         }
         return r;
      }

      static void test_modulus(Test::Result& result, Botan::RandomNumberGenerator& rng, const Botan::BigInt& p) {
         const size_t p_bits = p.bits();
         const Botan::Montgomery_Params params(p);
         const auto mod_p = Botan::Barrett_Reduction::for_public_modulus(p);

         const Botan::BigInt x(rng, p_bits - 1);

         std::vector<std::pair<Botan::BigInt, Botan::BigInt>> cases;

         if(p_bits <= 2048) {
            const Botan::BigInt k_full(rng, p_bits);
            const Botan::BigInt k_short(rng, p_bits / 2);

            cases = {
               {Botan::BigInt::zero(), k_full},
               {Botan::BigInt::one(), k_short},
               {p - 1, k_short},
               {x, Botan::BigInt::zero()},
               {x, Botan::BigInt::one()},
               {x, k_full},
               {x, k_short},
               {x, p - 1},
               {x, Botan::BigInt::power_of_2(p_bits - 1)},
            };
         } else {
            // Larger sizes are expensive, especially without IFMA, so use short exponents
            const Botan::BigInt k(rng, p_bits / 4);

            cases = {
               {x, k},
               {p - 1, k},
               {x, Botan::BigInt::one()},
            };
         }

         const std::string desc = " mod " + std::to_string(p_bits) + " bit p";

         for(const auto& [base, exp] : cases) {
            const auto expected = ref_powmod(base, exp, mod_p);

            // Both the exact length and the padded length used by blinded RSA exponents
            result.test_bn_eq("exp" + desc, Botan::monty_exp(params, base, exp, exp.bits()).value(), expected);
            result.test_bn_eq("padded exp" + desc, Botan::monty_exp(params, base, exp, p_bits + 64).value(), expected);
            result.test_bn_eq("vartime exp" + desc, Botan::monty_exp_vartime(params, base, exp).value(), expected);
         }
      }
};

BOTAN_REGISTER_TEST("math", "monty_exp", Montgomery_Exponentiation_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
