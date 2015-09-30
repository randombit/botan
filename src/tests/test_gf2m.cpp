/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MCELIECE)

#include <botan/gf2m_small_m.h>

BOTAN_TEST_CASE(gf2m, "GF(2^m)", {

   using namespace Botan;

   for(size_t degree = 2; degree <= 16; ++degree)
      {
      GF2m_Field field(degree);

      for(size_t i = 0; i <= field.gf_ord(); ++i)
         {
         gf2m a = i;

         BOTAN_TEST(field.gf_square(a), field.gf_mul(a, a), "Square and multiply");

         /*
         * This sequence is from the start of gf2m_decomp_rootfind_state::calc_Fxj_j_neq_0
         */
            {
            const gf2m jl_gray = field.gf_l_from_n(a);
            gf2m xl_j_tt_5 = field.gf_square_rr(jl_gray);
            const gf2m xl_gray_tt_3 = field.gf_mul_rrr(xl_j_tt_5, jl_gray);
            xl_j_tt_5 = field.gf_mul_rrr(xl_j_tt_5, xl_gray_tt_3);
            gf2m s = field.gf_mul_nrr(xl_gray_tt_3, field.gf_ord());
            BOTAN_CONFIRM(s <= field.gf_ord(), "Less than order");
            }
         }
      }
   });

#else

SKIP_TEST(gf2m);

#endif
