/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MCELIECE)
   #include <botan/gf2m_small_m.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_MCELIECE)

class GF2m_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_gf_overflow());

         return results;
         }

   private:
      Test::Result test_gf_overflow()
         {
         Test::Result result("GF2m");

         /*
         * This is testing one specific case where an overflow
         * occurred. It should be extended to test more of the interface.
         */
         for(size_t degree = 2; degree <= 16; ++degree)
            {
            Botan::GF2m_Field field(degree);

            using Botan::gf2m;

            for(size_t i = 0; i <= field.gf_ord(); ++i)
               {
               gf2m a = i;

               result.test_eq("square vs multiply",
                              static_cast<size_t>(field.gf_square(a)),
                              static_cast<size_t>(field.gf_mul(a, a)));

               /*
               * This sequence is from the start of gf2m_decomp_rootfind_state::calc_Fxj_j_neq_0
               */
                  {
                  const gf2m jl_gray = field.gf_l_from_n(a);
                  const gf2m xl_j_tt_5 = field.gf_square_rr(jl_gray);
                  const gf2m xl_gray_tt_3 = field.gf_mul_rrr(xl_j_tt_5, jl_gray);
                  gf2m s = field.gf_mul_nrr(xl_gray_tt_3, field.gf_ord());

                  result.test_gte("Value less than order", field.gf_ord(), s);
                  }
               }
            }
         return result;
         }
   };

BOTAN_REGISTER_TEST("gf2m", GF2m_Tests);

#endif

}

}
