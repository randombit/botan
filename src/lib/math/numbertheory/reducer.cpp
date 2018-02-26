/*
* Modular Reducer
* (C) 1999-2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/reducer.h>
#include <botan/internal/mp_core.h>

namespace Botan {

/*
* Modular_Reducer Constructor
*/
Modular_Reducer::Modular_Reducer(const BigInt& mod)
   {
   if(mod <= 0)
      throw Invalid_Argument("Modular_Reducer: modulus must be positive");

   m_modulus = mod;
   m_mod_words = m_modulus.sig_words();

   m_modulus_2 = Botan::square(m_modulus);

   m_mu = BigInt::power_of_2(2 * MP_WORD_BITS * m_mod_words) / m_modulus;
   }

/*
* Barrett Reduction
*/
BigInt Modular_Reducer::reduce(const BigInt& x) const
   {
   if(m_mod_words == 0)
      throw Invalid_State("Modular_Reducer: Never initalized");

   const size_t x_sw = x.sig_words();

   if(x_sw < m_mod_words || x.cmp(m_modulus, false) < 0)
      {
      if(x.is_negative())
         return x + m_modulus; // make positive
      return x;
      }
   else if(x.cmp(m_modulus_2, false) < 0)
      {
      secure_vector<word> ws;

      BigInt t1(x.data() + m_mod_words - 1, x_sw - (m_mod_words - 1));

      t1.mul(m_mu, ws);
      t1 >>= (MP_WORD_BITS * (m_mod_words + 1));

      t1.mul(m_modulus, ws);
      t1.mask_bits(MP_WORD_BITS * (m_mod_words + 1));

      t1.rev_sub(x.data(), std::min(x_sw, m_mod_words + 1), ws);

      if(t1.is_negative())
         {
         t1 += BigInt::power_of_2(MP_WORD_BITS * (m_mod_words + 1));
         }

      t1.reduce_below(m_modulus, ws);

      if(x.is_positive())
         return t1;
      else
         return (m_modulus - t1);
      }
   else
      {
      // too big, fall back to normal division
      return (x % m_modulus);
      }
   }

}
