/*
* Montgomery Exponentiation
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/def_powm.h>
#include <botan/numthry.h>
#include <botan/internal/mp_core.h>

namespace Botan {

/*
* Set the exponent
*/
void Montgomery_Exponentiator::set_exponent(const BigInt& exp)
   {
   m_exp = exp;
   m_exp_bits = exp.bits();
   }

/*
* Set the base
*/
void Montgomery_Exponentiator::set_base(const BigInt& base)
   {
   m_window_bits = Power_Mod::window_bits(m_exp.bits(), base.bits(), m_hints);

   m_g.resize((1 << m_window_bits) - 1);

   secure_vector<word> z(2 * (m_mod_words + 1));
   secure_vector<word> workspace(z.size());

   m_g[0] = (base >= m_modulus) ? (base % m_modulus) : base;

   bigint_monty_mul(&z[0], z.size(),
                    m_g[0].data(), m_g[0].size(), m_g[0].sig_words(),
                    m_R2_mod.data(), m_R2_mod.size(), m_R2_mod.sig_words(),
                    m_modulus.data(), m_mod_words, m_mod_prime,
                    &workspace[0]);

   m_g[0].assign(&z[0], m_mod_words + 1);

   const BigInt& x = m_g[0];
   const size_t x_sig = x.sig_words();

   for(size_t i = 1; i != m_g.size(); ++i)
      {
      const BigInt& y = m_g[i-1];
      const size_t y_sig = y.sig_words();

      zeroise(z);
      bigint_monty_mul(&z[0], z.size(),
                       x.data(), x.size(), x_sig,
                       y.data(), y.size(), y_sig,
                       m_modulus.data(), m_mod_words, m_mod_prime,
                       &workspace[0]);

      m_g[i].assign(&z[0], m_mod_words + 1);
      }
   }

/*
* Compute the result
*/
BigInt Montgomery_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (m_exp_bits + m_window_bits - 1) / m_window_bits;

   BigInt x = m_R_mod;
   secure_vector<word> z(2 * (m_mod_words + 1));
   secure_vector<word> workspace(2 * (m_mod_words + 1));

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t k = 0; k != m_window_bits; ++k)
         {
         zeroise(z);

         bigint_monty_sqr(&z[0], z.size(),
                          x.data(), x.size(), x.sig_words(),
                          m_modulus.data(), m_mod_words, m_mod_prime,
                          &workspace[0]);

         x.assign(&z[0], m_mod_words + 1);
         }

      if(u32bit nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits))
         {
         const BigInt& y = m_g[nibble-1];

         zeroise(z);
         bigint_monty_mul(&z[0], z.size(),
                          x.data(), x.size(), x.sig_words(),
                          y.data(), y.size(), y.sig_words(),
                          m_modulus.data(), m_mod_words, m_mod_prime,
                          &workspace[0]);

         x.assign(&z[0], m_mod_words + 1);
         }
      }

   x.get_reg().resize(2*m_mod_words+1);

   bigint_monty_redc(&x[0], x.size(),
                     m_modulus.data(), m_mod_words, m_mod_prime,
                     &workspace[0]);

   x.get_reg().resize(m_mod_words+1);

   return x;
   }

/*
* Montgomery_Exponentiator Constructor
*/
Montgomery_Exponentiator::Montgomery_Exponentiator(const BigInt& mod,
                                                   Power_Mod::Usage_Hints hints)
   {
   // Montgomery reduction only works for positive odd moduli
   if(!mod.is_positive() || mod.is_even())
      throw Invalid_Argument("Montgomery_Exponentiator: invalid modulus");

   m_window_bits = 0;
   m_hints = hints;
   m_modulus = mod;

   m_mod_words = m_modulus.sig_words();

   const BigInt b = BigInt(1) << BOTAN_MP_WORD_BITS;
   m_mod_prime = (b - inverse_mod(m_modulus.word_at(0), b)).word_at(0);

   const BigInt r(BigInt::Power2, m_mod_words * BOTAN_MP_WORD_BITS);
   m_R_mod = r % m_modulus;
   m_R2_mod = (m_R_mod * m_R_mod) % m_modulus;
   }

}
