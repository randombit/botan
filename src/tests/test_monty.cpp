/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/exceptn.h>
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

         // The largest value accepted by mul_by_word
         const Botan::word max_mul = static_cast<Botan::word>(-1) >> 2;

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

            auto z = monty_x;
            z += monty_y;
            result.test_bn_eq("Montgomery in-place addition", z.value(), (x + y) % p);

            z = monty_x;
            z -= monty_y;
            result.test_bn_eq("Montgomery in-place subtraction", z.value(), (x - y) % p);

            z = monty_x;
            z += z;
            result.test_bn_eq("Montgomery in-place doubling", z.value(), (x + x) % p);

            z = monty_x;
            z.div2();
            result.test_bn_eq("Montgomery div2", (z.value() * 2) % p, x);

            for(const Botan::word d : {Botan::word(0),
                                       Botan::word(1),
                                       Botan::word(2),
                                       Botan::word(3),
                                       Botan::word(5),
                                       Botan::word(7),
                                       Botan::word(17),
                                       Botan::word(255),
                                       Botan::word(1024),
                                       Botan::word(65537),
                                       max_mul}) {
               z = monty_x;
               z.mul_by_word(d);
               result.test_bn_eq("Montgomery mul_by_word " + std::to_string(d), z.value(), (x * d) % p);
            }

            z = monty_x;
            result.test_throws<Botan::Invalid_Argument>("Montgomery mul_by_word rejects large multiplier",
                                                        [&]() { z.mul_by_word(max_mul + 1); });

            z = monty_x;
            z.ct_cond_assign(false, monty_y);
            result.test_bn_eq("Montgomery ct_cond_assign false", z.value(), x);
            z.ct_cond_assign(true, monty_y);
            result.test_bn_eq("Montgomery ct_cond_assign true", z.value(), y);

            z = monty_x;
            z.ct_cond_negate(false);
            result.test_bn_eq("Montgomery ct_cond_negate false", z.value(), x);
            z.ct_cond_negate(true);
            result.test_bn_eq("Montgomery ct_cond_negate true", z.value(), p - x);

            z = Botan::Montgomery_Int(params);
            z.ct_cond_negate(true);
            result.test_is_true("Montgomery ct_cond_negate of zero is zero", z.is_zero());

            // NOLINTNEXTLINE(*-redundant-expression)
            result.test_is_true("Montgomery x - x is zero", (monty_x - monty_x).is_zero());
            result.test_is_false("Montgomery x is not zero", monty_x.is_zero());

            results.push_back(result);
         }

         /*
         * Moduli whose leading word is all ones or is 1, which are edge cases
         * of the quotient estimate in mul_by_word
         */
         Test::Result mul_result("Montgomery_Int mul_by_word");

         for(const char* p_hex : {"0x3",
                                  "0xFFFFFFFFFFFFFFC5",
                                  "0x1000000000000000D",
                                  "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                                  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61",
                                  "0x100000000000000000000000000000000000000000000000000000000000000BD"}) {
            const Botan::BigInt p(p_hex);
            const Botan::Montgomery_Params params(p);

            for(size_t i = 0; i != 50; ++i) {
               const auto x = Botan::BigInt::random_integer(*rng, 0, p);
               const Botan::word d = [&]() -> Botan::word {
                  if(i < 2) {
                     return max_mul - i;
                  }
                  const auto r = Botan::BigInt::random_integer(*rng, 0, Botan::BigInt::from_word(max_mul)).word_at(0);
                  return (i % 2 == 0) ? r : (r & 0xFF);
               }();

               auto z = Botan::Montgomery_Int(params, x, true);
               z.mul_by_word(d);
               mul_result.test_bn_eq("Montgomery mul_by_word", z.value(), (x * d) % p);
            }
         }

         results.push_back(mul_result);

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
            const auto precomp = Botan::monty_precompute(params, g, window);
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
