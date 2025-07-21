/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NUMBERTHEORY)
   #include <botan/numthry.h>
   #include <botan/internal/monty.h>
#endif

namespace Botan_Tests {

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
            auto p = Botan::random_prime(*rng, p_bits);

            auto params = std::make_shared<Botan::Montgomery_Params>(p);

            auto x = Botan::BigInt::random_integer(*rng, 1, p);
            auto y = Botan::BigInt::random_integer(*rng, 1, p);

            auto monty_x = Botan::Montgomery_Int(params, x, true);
            auto monty_y = Botan::Montgomery_Int(params, y, true);

            result.test_eq("Montgomery addition", (monty_x + monty_y).value(), (x + y) % p);
            result.test_eq("Montgomery subtraction", (monty_x - monty_y).value(), (x - y) % p);
            result.test_eq("Montgomery multiplication", (monty_x.mul(monty_y, ws)).value(), (x * y) % p);

            result.test_eq("Montgomery square x", (monty_x.square(ws)).value(), (x * x) % p);
            result.test_eq("Montgomery square y", (monty_y.square(ws)).value(), (y * y) % p);

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("math", "monty_int", Montgomery_Integer_Tests);

#endif

}  // namespace Botan_Tests
