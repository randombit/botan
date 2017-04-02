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

class MP_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_cnd_swap());
         results.push_back(test_cnd_add());
         results.push_back(test_cnd_sub());
         results.push_back(test_cnd_abs());

         return results;
         }
   private:
      Result test_cnd_add()
         {
         Result result("bigint_cnd_add");

         using namespace Botan;

         const word max = MP_WORD_MAX;

         word a = 2;
         word c = bigint_cnd_add(0, &a, &max, 1);

         result.test_int_eq(a, 2, "No op");
         result.test_int_eq(c, 0, "No op");

         c = bigint_cnd_add(1, &a, &max, 1);

         result.test_int_eq(a, 1, "Add");
         result.test_int_eq(c, 1, "Carry");

         // TODO more tests

         return result;
         }

      Result test_cnd_sub()
         {
         Result result("bigint_cnd_sub");

         using namespace Botan;

         word a = 2;
         word b = 3;
         word c = bigint_cnd_sub(0, &a, &b, 1);

         result.test_int_eq(a, 2, "No op");
         result.test_int_eq(c, 0, "No op");

         c = bigint_cnd_sub(1, &a, &b, 1);

         result.test_int_eq(a, MP_WORD_MAX, "Sub");
         result.test_int_eq(c, 1, "Borrow");

         return result;
         }

      Result test_cnd_abs()
         {
         Result result("bigint_cnd_abs");

         using namespace Botan;

         word x1 = MP_WORD_MAX;
         bigint_cnd_abs(1, &x1, 1);
         result.test_int_eq(x1, 1, "Abs");

         x1 = 0;
         bigint_cnd_abs(1, &x1, 1);
         result.test_int_eq(x1, 0, "Abs");

         x1 = 1;
         bigint_cnd_abs(1, &x1, 1);
         result.test_int_eq(x1, MP_WORD_MAX, "Abs");

         x1 = 1;
         bigint_cnd_abs(0, &x1, 1);
         result.test_int_eq(x1, 1, "No change");

         word x2[2] = { MP_WORD_MAX, MP_WORD_MAX };

         bigint_cnd_abs(1, x2, 2);
         result.test_int_eq(x2[0], 1, "Abs");
         result.test_int_eq(x2[1], 0, "Abs");

         return result;
         }

      Result test_cnd_swap()
         {
         Result result("bigint_cnd_swap");

         using namespace Botan;

         // null with zero length is ok
         bigint_cnd_swap(0, nullptr, nullptr, 0);
         bigint_cnd_swap(1, nullptr, nullptr, 0);

         word x1 = 5, y1 = 9;

         bigint_cnd_swap(0, &x1, &y1, 1);
         result.test_int_eq(x1, 5, "No swap");
         bigint_cnd_swap(1, &x1, &y1, 1);
         result.test_int_eq(x1, 9, "Swap");

         word x5[5] = { 0, 1, 2, 3, 4 };
         word y5[5] = { 3, 2, 1, 0, 9 };

         // Should only modify first four
         bigint_cnd_swap(1, x5, y5, 4);

         for(size_t i = 0; i != 4; ++i)
            {
            result.test_int_eq(x5[i], 3 - i, "Swap x5");
            }
         result.test_int_eq(x5[4], 4, "Not touched");

         for(size_t i = 0; i != 4; ++i)
            {
            result.test_int_eq(y5[i], i, "Swap y5");
            }
         result.test_int_eq(y5[4], 9, "Not touched");

         return result;
         }
   };

BOTAN_REGISTER_TEST("mp_unit", MP_Unit_Tests);

#endif

}

}
