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
#include <botan/code_based_util.h>
#include <string>

namespace Botan {

namespace gf2m_small_m {

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

}

u32bit encode_gf2m(gf2m to_enc, byte* mem)
   {
   mem[0] = to_enc >> 8;
   mem[1] = to_enc & 0xFF;
   return sizeof(to_enc);
   }

gf2m decode_gf2m(const byte* mem)
   {
   gf2m result;
   result = mem[0] << 8;
   result |= mem[1];
   return result;
   }

// construct the table gf_exp[i]=alpha^i
void Gf2m_Field::init_exp()
   {
   m_gf_exp_table.resize(1 << get_extension_degree());

   m_gf_exp_table[0] = 1;
   for(size_t i = 1; i < gf_ord(); ++i)
      {
      m_gf_exp_table[i] = m_gf_exp_table[i - 1] << 1;
      if (m_gf_exp_table[i - 1] & (1 << (get_extension_degree()-1)))
         {
         m_gf_exp_table[i] ^= prim_poly[get_extension_degree()];
         }
      }

   // hack for the multiplication
   m_gf_exp_table[gf_ord()] = 1;
   }

// construct the table gf_log[alpha^i]=i
void Gf2m_Field::init_log()
   {
   m_gf_log_table.resize(1 << get_extension_degree());

   m_gf_log_table[0] = gf_ord(); // log of 0 par convention
   for (size_t i = 0; i < gf_ord() ; ++i)
      {
      m_gf_log_table[m_gf_exp_table[i]] = i;
      }
   }


Gf2m_Field::Gf2m_Field(size_t extdeg)
   {
   if(extdeg < 2 || extdeg > MAX_EXT_DEG)
      throw std::runtime_error("Gf2m_Field does not support degree " + std::to_string(extdeg));

   m_gf_extension_degree = extdeg;
   m_gf_cardinality = 1 << extdeg;
   m_gf_multiplicative_order = m_gf_cardinality - 1;

   init_exp();
   init_log();
   }

gf2m Gf2m_Field::gf_div(gf2m x, gf2m y)
   {
   s32bit sub_res = ((s32bit)m_gf_log_table[x]) - ((s32bit) m_gf_log_table[y]);
   s32bit modq_res = ((s32bit)_gf_modq_1(sub_res));
   s32bit div_res = (((s32bit)x) ? ((s32bit) m_gf_exp_table[modq_res]) : 0  );
   return (gf2m) div_res;
   }

// we suppose i >= 0. Par convention 0^0 = 1
gf2m Gf2m_Field::gf_pow(gf2m x, int i)
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
      i *= m_gf_log_table[x];
      while (i >> get_extension_degree())
         i = (i & (gf_ord())) + (i >> get_extension_degree());
      return m_gf_exp_table[i];
      }
   }

}

}
