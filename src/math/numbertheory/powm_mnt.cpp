/*
* Montgomery Exponentiation
* (C) 1999-2010,2012 Jack Lloyd
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

   m_g.resize((1 << m_window_bits));

   BigInt z(BigInt::Positive, 2 * (m_mod_words + 1));
   secure_vector<word> workspace(z.size());

   m_g[0] = 1;

   bigint_monty_mul(z.mutable_data(), z.size(),
                    m_g[0].data(), m_g[0].size(), m_g[0].sig_words(),
                    m_R2_mod.data(), m_R2_mod.size(), m_R2_mod.sig_words(),
                    m_modulus.data(), m_mod_words, m_mod_prime,
                    &workspace[0]);

   m_g[0] = z;

   m_g[1] = (base >= m_modulus) ? (base % m_modulus) : base;

   bigint_monty_mul(z.mutable_data(), z.size(),
                    m_g[1].data(), m_g[1].size(), m_g[1].sig_words(),
                    m_R2_mod.data(), m_R2_mod.size(), m_R2_mod.sig_words(),
                    m_modulus.data(), m_mod_words, m_mod_prime,
                    &workspace[0]);

   m_g[1] = z;

   const BigInt& x = m_g[1];
   const size_t x_sig = x.sig_words();

   for(size_t i = 2; i != m_g.size(); ++i)
      {
      const BigInt& y = m_g[i-1];
      const size_t y_sig = y.sig_words();

      bigint_monty_mul(z.mutable_data(), z.size(),
                       x.data(), x.size(), x_sig,
                       y.data(), y.size(), y_sig,
                       m_modulus.data(), m_mod_words, m_mod_prime,
                       &workspace[0]);

      m_g[i] = z;
      }
   }

/*
* Compute the result
*/
BigInt Montgomery_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (m_exp_bits + m_window_bits - 1) / m_window_bits;

   BigInt x = m_R_mod;

   const size_t z_size = 2*(m_mod_words + 1);

   BigInt z(BigInt::Positive, z_size);
   secure_vector<word> workspace(z_size);

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t k = 0; k != m_window_bits; ++k)
         {
         bigint_monty_sqr(z.mutable_data(), z_size,
                          x.data(), x.size(), x.sig_words(),
                          m_modulus.data(), m_mod_words, m_mod_prime,
                          &workspace[0]);

         x = z;
         }

      const u32bit nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits);

      const BigInt& y = m_g[nibble];

      bigint_monty_mul(z.mutable_data(), z_size,
                       x.data(), x.size(), x.sig_words(),
                       y.data(), y.size(), y.sig_words(),
                       m_modulus.data(), m_mod_words, m_mod_prime,
                       &workspace[0]);

      x = z;
      }

   x.grow_to(2*m_mod_words + 1);

   bigint_monty_redc(x.mutable_data(),
                     m_modulus.data(), m_mod_words, m_mod_prime,
                     &workspace[0]);

   return x;
   }

/*
* Montgomery_Exponentiator Constructor
*/
Montgomery_Exponentiator::Montgomery_Exponentiator(const BigInt& mod,
                                                   Power_Mod::Usage_Hints hints) :
   m_modulus(mod),
   m_mod_words(m_modulus.sig_words()),
   m_window_bits(1),
   m_hints(hints)
   {
   // Montgomery reduction only works for positive odd moduli
   if(!m_modulus.is_positive() || m_modulus.is_even())
      throw Invalid_Argument("Montgomery_Exponentiator: invalid modulus");

   m_mod_prime = monty_inverse(mod.word_at(0));

   const BigInt r = BigInt::power_of_2(m_mod_words * BOTAN_MP_WORD_BITS);
   m_R_mod = r % m_modulus;
   m_R2_mod = (m_R_mod * m_R_mod) % m_modulus;
   }

}
