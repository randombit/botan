/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BIGINT_MP)
   #include <botan/rng.h>
   #include <botan/internal/mp_core.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_BIGINT_MP)

class MP_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_cnd_swap());
         results.push_back(test_cnd_add());
         results.push_back(test_cnd_sub());
         results.push_back(test_cnd_abs());
         results.push_back(test_reciprocal_word(rng()));
         results.push_back(test_divide_precomp(rng()));

         return results;
      }

   private:
      static Result test_cnd_add() {
         Result result("bigint_cnd_add");

         const Botan::word max = ~static_cast<Botan::word>(0);

         Botan::word a = 2;
         Botan::word c = Botan::bigint_cnd_add<Botan::word>(0, &a, &max, 1);

         result.test_u64_eq("No op", a, 2);
         result.test_u64_eq("No op", c, 0);

         c = Botan::bigint_cnd_add<Botan::word>(1, &a, &max, 1);

         result.test_u64_eq("Add", a, 1);
         result.test_u64_eq("Carry", c, 1);

         // TODO more tests

         return result;
      }

      static Result test_cnd_sub() {
         Result result("bigint_cnd_sub");

         Botan::word a = 2;
         const Botan::word b = 3;
         Botan::word c = Botan::bigint_cnd_sub<Botan::word>(0, &a, &b, 1);

         result.test_u64_eq("No op", a, 2);
         result.test_u64_eq("No op", c, 0);

         c = Botan::bigint_cnd_sub<Botan::word>(1, &a, &b, 1);

         result.test_u64_eq("Sub", a, ~static_cast<Botan::word>(0));
         result.test_u64_eq("Borrow", c, 1);

         return result;
      }

      static Result test_cnd_abs() {
         Result result("bigint_cnd_abs");

         const Botan::word max = Botan::WordInfo<Botan::word>::max;

         Botan::word x1 = max;
         Botan::bigint_cnd_abs<Botan::word>(1, &x1, 1);
         result.test_u64_eq("Abs", x1, 1);

         x1 = 0;
         Botan::bigint_cnd_abs<Botan::word>(1, &x1, 1);
         result.test_u64_eq("Abs", x1, 0);

         x1 = 1;
         Botan::bigint_cnd_abs<Botan::word>(1, &x1, 1);
         result.test_u64_eq("Abs", x1, max);

         x1 = 1;
         Botan::bigint_cnd_abs<Botan::word>(0, &x1, 1);
         result.test_u64_eq("No change", x1, 1);

         Botan::word x2[2] = {max, max};

         Botan::bigint_cnd_abs<Botan::word>(1, x2, 2);
         result.test_u64_eq("Abs", x2[0], 1);
         result.test_u64_eq("Abs", x2[1], 0);

         return result;
      }

      static Result test_cnd_swap() {
         Result result("bigint_cnd_swap");

         // null with zero length is ok
         Botan::bigint_cnd_swap<Botan::word>(0, nullptr, nullptr, 0);
         Botan::bigint_cnd_swap<Botan::word>(1, nullptr, nullptr, 0);

         Botan::word x1 = 5;
         Botan::word y1 = 9;

         Botan::bigint_cnd_swap<Botan::word>(0, &x1, &y1, 1);
         result.test_u64_eq("No swap", x1, 5);
         Botan::bigint_cnd_swap<Botan::word>(1, &x1, &y1, 1);
         result.test_u64_eq("Swap", x1, 9);

         Botan::word x5[5] = {0, 1, 2, 3, 4};
         Botan::word y5[5] = {3, 2, 1, 0, 9};

         // Should only modify first four
         Botan::bigint_cnd_swap<Botan::word>(1, x5, y5, 4);

         for(size_t i = 0; i != 4; ++i) {
            result.test_u64_eq("Swap x5", x5[i], static_cast<Botan::word>(3 - i));
         }
         result.test_u64_eq("Not touched", x5[4], 4);

         for(size_t i = 0; i != 4; ++i) {
            result.test_u64_eq("Swap y5", y5[i], static_cast<Botan::word>(i));
         }
         result.test_u64_eq("Not touched", y5[4], 9);

         return result;
      }

      template <typename W>
      static W random_word(Botan::RandomNumberGenerator& rng) {
         uint8_t buf[sizeof(W)];
         rng.randomize(buf, sizeof(buf));

         W x = 0;
         for(const uint8_t b : buf) {
            x = static_cast<W>((x << 8) | b);
         }
         return x;
      }

      static Result test_reciprocal_word(Botan::RandomNumberGenerator& rng) {
         Result result("reciprocal_word");

         // Test constexpr execution:
         static_assert(Botan::reciprocal_word<uint32_t>(0x80000000) == 0xFFFFFFFF);
         static_assert(Botan::reciprocal_word<uint32_t>(0xFFFFFFFF) == 1);
         static_assert(Botan::reciprocal_word<uint64_t>(0x8000000000000000) == 0xFFFFFFFFFFFFFFFF);
         static_assert(Botan::reciprocal_word<uint64_t>(0xFFFFFFFFFFFFFFFF) == 1);

         test_reciprocal_word_for<uint32_t>(result, rng);
         test_reciprocal_word_for<uint64_t>(result, rng);

         return result;
      }

      template <typename W>
      static void test_reciprocal_word_for(Result& result, Botan::RandomNumberGenerator& rng) {
         constexpr W max = Botan::WordInfo<W>::max;
         constexpr W top_bit = Botan::WordInfo<W>::top_bit;

         std::vector<W> divisors{top_bit, static_cast<W>(top_bit + 1), static_cast<W>(max - 1), max};

         for(size_t i = 0; i != 256; ++i) {
            divisors.push_back(random_word<W>(rng) | top_bit);
         }

         for(const W d : divisors) {
            const W v = Botan::reciprocal_word<W>(d);

            /*
            * Verify 0 < 2^(2b) - (2^b + v)*d <= d, which uniquely
            * determines v == floor((2^(2b) - 1) / d) - 2^b
            */
            W hi = 0;
            const W lo = Botan::word_madd2(v, d, &hi);

            // (2^b + v)*d == (hi + d) || lo; it must not exceed 2^(2b) - 1
            const W hi_d = static_cast<W>(hi + d);
            const bool fits = (hi_d > hi);
            result.test_is_true("reciprocal_word hi_d > hi", fits);

            // Adding d once more must carry out of 2b bits
            const bool carry_out = (static_cast<W>(lo + d) < lo) && (hi_d == max);

            result.test_is_true("reciprocal_word carry_out", carry_out);
         }
      }

      static Result test_divide_precomp(Botan::RandomNumberGenerator& rng) {
         Result result("divide_precomp");

         test_divide_precomp_for<uint32_t>(result, rng);
         test_divide_precomp_for<uint64_t>(result, rng);

         return result;
      }

      template <typename W>
      static void test_divide_precomp_for(Result& result, Botan::RandomNumberGenerator& rng) {
         constexpr W max = Botan::WordInfo<W>::max;
         constexpr W top_bit = Botan::WordInfo<W>::top_bit;

         std::vector<W> divisors{1,
                                 2,
                                 3,
                                 58,
                                 627,
                                 12345,
                                 static_cast<W>(0xDEADBEEF),
                                 static_cast<W>(top_bit - 1),
                                 top_bit,
                                 static_cast<W>(top_bit + 1),
                                 static_cast<W>(max - 1),
                                 max};

         // Random divisors of varying magnitudes
         for(size_t i = 0; i != 128; ++i) {
            const size_t shift = random_word<W>(rng) % Botan::WordInfo<W>::bits;
            divisors.push_back((random_word<W>(rng) >> shift) | 1);
         }

         for(const W d : divisors) {
            const auto div = Botan::divide_precomp<W>::setup_vartime(d);

            std::vector<std::pair<W, W>> cases{{0, 0},
                                               {0, max},
                                               {0, static_cast<W>(d - 1)},
                                               {0, d},
                                               {static_cast<W>(d - 1), 0},
                                               {static_cast<W>(d - 1), max}};

            for(size_t i = 0; i != 128; ++i) {
               cases.emplace_back(static_cast<W>(random_word<W>(rng) % d), random_word<W>(rng));
            }

            /*
            * Numerators equal or adjacent to exact multiples of d, which
            * exercise the quotient correction boundaries
            */
            for(size_t i = 0; i != 64; ++i) {
               const W q = random_word<W>(rng);

               for(const W delta : {static_cast<W>(0), static_cast<W>(1), static_cast<W>(d - 1)}) {
                  if(delta >= d) {
                     continue;
                  }
                  W hi = delta;
                  const W lo = Botan::word_madd2(q, d, &hi);
                  cases.emplace_back(hi, lo);
               }
            }

            for(const auto& [n1, n0] : cases) {
               // Check that q * d + r == (n1:n0) and r < d

               const auto [q_ct, r_ct] = div.divmod_2to1_ct(n1, n0);

               const auto [q, r] = div.divmod_2to1_vartime(n1, n0);

               result.test_u64_eq("divmod_2to1 vartime and ct q agree", q, q_ct);
               result.test_u64_eq("divmod_2to1 vartime and ct q agree", r, r_ct);

               W hi = r;
               const W lo = Botan::word_madd2(q, d, &hi);

               result.test_is_true("div_2to1 r < d", r < d);
               result.test_is_true("div_2to1 lo == n0", lo == n0);
               result.test_is_true("div_2to1 hi == n1", hi == n1);
            }
         }
      }
};

BOTAN_REGISTER_TEST("math", "mp_unit", MP_Unit_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
