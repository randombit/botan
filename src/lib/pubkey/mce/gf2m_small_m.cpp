/*
* (C) Copyright Projet SECRET, INRIA, Rocquencourt
* (C) Bhaskar Biswas and  Nicolas Sendrier
*
* (C) 2014 cryptosource GmbH
* (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gf2m_small_m.h>
#include <botan/exceptn.h>
#include <string>

namespace Botan {

#define MAX_EXT_DEG 16

namespace {

unsigned int prim_poly[MAX_EXT_DEG + 1] = {
   01,		/* extension degree 0 (!) never used */
   03,		/* extension degree 1 (!) never used */
   07, 		/* extension degree 2 */
   013, 		/* extension degree 3 */
   023, 		/* extension degree 4 */
   045, 		/* extension degree 5 */
   0103, 		/* extension degree 6 */
   0203, 		/* extension degree 7 */
   0435, 		/* extension degree 8 */
   01041, 		/* extension degree 9 */
   02011,		/* extension degree 10 */
   04005,		/* extension degree 11 */
   010123,		/* extension degree 12 */
   020033,		/* extension degree 13 */
   042103,		/* extension degree 14 */
   0100003,		/* extension degree 15 */
   0210013		/* extension degree 16 */
};

std::vector<gf2m> gf_exp_table(size_t deg, gf2m prime_poly)
   {
   // construct the table gf_exp[i]=alpha^i

   std::vector<gf2m> tab((1 << deg) + 1);

   tab[0] = 1;
   for(size_t i = 1; i < tab.size(); ++i)
      {
      const bool overflow = tab[i - 1] >> (deg - 1);
      tab[i] = (tab[i-1] << 1) ^ (overflow ? prime_poly : 0);
      }

   return tab;
   }

const std::vector<gf2m>& exp_table(size_t deg)
   {
   static std::vector<gf2m> tabs[MAX_EXT_DEG + 1];

   if(deg < 2 || deg > MAX_EXT_DEG)
      throw Exception("GF2m_Field does not support degree " + std::to_string(deg));

   if(tabs[deg].empty())
      tabs[deg] = gf_exp_table(deg, prim_poly[deg]);

   return tabs[deg];
   }

std::vector<gf2m> gf_log_table(size_t deg, const std::vector<gf2m>& exp)
   {
   std::vector<gf2m> tab(1 << deg);

   tab[0] = (1 << deg) - 1; // log of 0 is the order by convention
   for (size_t i = 0; i < tab.size(); ++i)
      {
      tab[exp[i]] = i;
      }
   return tab;
   }

const std::vector<gf2m>& log_table(size_t deg)
   {
   static std::vector<gf2m> tabs[MAX_EXT_DEG + 1];

   if(deg < 2 || deg > MAX_EXT_DEG)
      throw Exception("GF2m_Field does not support degree " + std::to_string(deg));

   if(tabs[deg].empty())
      tabs[deg] = gf_log_table(deg, exp_table(deg));

   return tabs[deg];
   }

}

uint32_t encode_gf2m(gf2m to_enc, uint8_t* mem)
   {
   mem[0] = to_enc >> 8;
   mem[1] = to_enc & 0xFF;
   return sizeof(to_enc);
   }

gf2m decode_gf2m(const uint8_t* mem)
   {
   gf2m result;
   result = mem[0] << 8;
   result |= mem[1];
   return result;
   }

GF2m_Field::GF2m_Field(size_t extdeg) : m_gf_extension_degree(extdeg),
                                        m_gf_multiplicative_order((1 << extdeg) - 1),
                                        m_gf_log_table(log_table(m_gf_extension_degree)),
                                        m_gf_exp_table(exp_table(m_gf_extension_degree))
   {
   }

gf2m GF2m_Field::gf_div(gf2m x, gf2m y) const
   {
   const int32_t sub_res = static_cast<int32_t>(gf_log(x) - static_cast<int32_t>(gf_log(y)));
   const int32_t modq_res = static_cast<int32_t>(_gf_modq_1(sub_res));
   const int32_t div_res = static_cast<int32_t>(x) ? static_cast<int32_t>(gf_exp(modq_res)) : 0;
   return static_cast<gf2m>(div_res);
   }

// we suppose i >= 0. Par convention 0^0 = 1
gf2m GF2m_Field::gf_pow(gf2m x, int i) const
   {
   if (i == 0)
      return 1;
   else if (x == 0)
      return 0;
   else
      {
      // i mod (q-1)
      while (i >> get_extension_degree())
         i = (i & (gf_ord())) + (i >> get_extension_degree());
      i *= gf_log(x);
      while (i >> get_extension_degree())
         i = (i & (gf_ord())) + (i >> get_extension_degree());
      return gf_exp(i);
      }
   }

}
