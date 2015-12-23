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

   if(x.cmp(m_modulus, false) < 0)
      {
      if(x.is_negative())
         return x + m_modulus; // make positive
      return x;
      }
   else if(x.cmp(m_modulus_2, false) < 0)
      {
      BigInt t1 = x;
      t1.set_sign(BigInt::Positive);
      t1 >>= (MP_WORD_BITS * (m_mod_words - 1));
      t1 *= m_mu;

      t1 >>= (MP_WORD_BITS * (m_mod_words + 1));
      t1 *= m_modulus;

      t1.mask_bits(MP_WORD_BITS * (m_mod_words + 1));

      BigInt t2 = x;
      t2.set_sign(BigInt::Positive);
      t2.mask_bits(MP_WORD_BITS * (m_mod_words + 1));

      t2 -= t1;

      if(t2.is_negative())
         {
         t2 += BigInt::power_of_2(MP_WORD_BITS * (m_mod_words + 1));
         }

      while(t2 >= m_modulus)
         t2 -= m_modulus;

      if(x.is_positive())
         return t2;
      else
         return (m_modulus - t2);
      }
   else
      {
      // too big, fall back to normal division
      return (x % m_modulus);
      }
   }

}
