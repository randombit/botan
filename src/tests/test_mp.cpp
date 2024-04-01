/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_BIGINT_MP)
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

         return results;
      }

   private:
      static Result test_cnd_add() {
         Result result("bigint_cnd_add");

         const Botan::word max = ~static_cast<Botan::word>(0);

         Botan::word a = 2;
         Botan::word c = Botan::bigint_cnd_add<Botan::word>(0, &a, &max, 1);

         result.test_int_eq(a, 2, "No op");
         result.test_int_eq(c, 0, "No op");

         c = Botan::bigint_cnd_add<Botan::word>(1, &a, &max, 1);

         result.test_int_eq(a, 1, "Add");
         result.test_int_eq(c, 1, "Carry");

         // TODO more tests

         return result;
      }

      static Result test_cnd_sub() {
         Result result("bigint_cnd_sub");

         Botan::word a = 2;
         Botan::word b = 3;
         Botan::word c = Botan::bigint_cnd_sub<Botan::word>(0, &a, &b, 1);

         result.test_int_eq(a, 2, "No op");
         result.test_int_eq(c, 0, "No op");

         c = Botan::bigint_cnd_sub<Botan::word>(1, &a, &b, 1);

         result.test_int_eq(a, ~static_cast<Botan::word>(0), "Sub");
         result.test_int_eq(c, 1, "Borrow");

         return result;
      }

      static Result test_cnd_abs() {
         Result result("bigint_cnd_abs");

         const Botan::word max = Botan::WordInfo<Botan::word>::max;

         Botan::word x1 = max;
         Botan::bigint_cnd_abs<Botan::word>(1, &x1, 1);
         result.test_int_eq(x1, 1, "Abs");

         x1 = 0;
         Botan::bigint_cnd_abs<Botan::word>(1, &x1, 1);
         result.test_int_eq(x1, 0, "Abs");

         x1 = 1;
         Botan::bigint_cnd_abs<Botan::word>(1, &x1, 1);
         result.test_int_eq(x1, max, "Abs");

         x1 = 1;
         Botan::bigint_cnd_abs<Botan::word>(0, &x1, 1);
         result.test_int_eq(x1, 1, "No change");

         Botan::word x2[2] = {max, max};

         Botan::bigint_cnd_abs<Botan::word>(1, x2, 2);
         result.test_int_eq(x2[0], 1, "Abs");
         result.test_int_eq(x2[1], 0, "Abs");

         return result;
      }

      static Result test_cnd_swap() {
         Result result("bigint_cnd_swap");

         // null with zero length is ok
         Botan::bigint_cnd_swap<Botan::word>(0, nullptr, nullptr, 0);
         Botan::bigint_cnd_swap<Botan::word>(1, nullptr, nullptr, 0);

         Botan::word x1 = 5, y1 = 9;

         Botan::bigint_cnd_swap<Botan::word>(0, &x1, &y1, 1);
         result.test_int_eq(x1, 5, "No swap");
         Botan::bigint_cnd_swap<Botan::word>(1, &x1, &y1, 1);
         result.test_int_eq(x1, 9, "Swap");

         Botan::word x5[5] = {0, 1, 2, 3, 4};
         Botan::word y5[5] = {3, 2, 1, 0, 9};

         // Should only modify first four
         Botan::bigint_cnd_swap<Botan::word>(1, x5, y5, 4);

         for(size_t i = 0; i != 4; ++i) {
            result.test_int_eq(x5[i], 3 - i, "Swap x5");
         }
         result.test_int_eq(x5[4], 4, "Not touched");

         for(size_t i = 0; i != 4; ++i) {
            result.test_int_eq(y5[i], i, "Swap y5");
         }
         result.test_int_eq(y5[4], 9, "Not touched");

         return result;
      }
};

BOTAN_REGISTER_TEST("math", "mp_unit", MP_Unit_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
