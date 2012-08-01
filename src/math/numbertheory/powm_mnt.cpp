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

namespace {

/*
* Compute -input^-1 mod 2^MP_WORD_BITS. We are assured that the
* inverse exists because input is odd (checked by checking that the
* modulus is odd in the Montgomery_Exponentiator constructor, and
* input is the low word of the modulus and thus also odd), and thus
* input and 2^n are relatively prime.
*/
word monty_inverse(word input)
   {
   word b = input;
   word x2 = 1, x1 = 0, y2 = 0, y1 = 1;

   // First iteration, a = n+1
   word q = bigint_divop(1, 0, b);
   word r = (MP_WORD_MAX - q*b) + 1;
   word x = x2 - q*x1;
   word y = y2 - q*y1;

   word a = b;
   b = r;
   x2 = x1;
   x1 = x;
   y2 = y1;
   y1 = y;

   while(b > 0)
      {
      q = a / b;
      r = a - q*b;
      x = x2 - q*x1;
      y = y2 - q*y1;

      a = b;
      b = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;
      }

   // Now invert in addition space
   y2 = (MP_WORD_MAX - y2) + 1;

   return y2;
   }

}

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

   BigInt z(BigInt::Positive, 2 * (m_mod_words + 1));
   secure_vector<word> workspace(z.size());

   m_g[0] = (base >= m_modulus) ? (base % m_modulus) : base;

   bigint_monty_mul(z.mutable_data(), z.size(),
                    m_g[0].data(), m_g[0].size(), m_g[0].sig_words(),
                    m_R2_mod.data(), m_R2_mod.size(), m_R2_mod.sig_words(),
                    m_modulus.data(), m_mod_words, m_mod_prime,
                    &workspace[0]);

   m_g[0] = z;

   const BigInt& x = m_g[0];
   const size_t x_sig = x.sig_words();

   for(size_t i = 1; i != m_g.size(); ++i)
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

      if(u32bit nibble = m_exp.get_substring(m_window_bits*(i-1), m_window_bits))
         {
         const BigInt& y = m_g[nibble-1];

         bigint_monty_mul(z.mutable_data(), z_size,
                          x.data(), x.size(), x.sig_words(),
                          y.data(), y.size(), y.sig_words(),
                          m_modulus.data(), m_mod_words, m_mod_prime,
                          &workspace[0]);

         x = z;
         }
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
