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
   this->exp = exp;
   exp_bits = exp.bits();
   }

/*
* Set the base
*/
void Montgomery_Exponentiator::set_base(const BigInt& base)
   {
   window_bits = Power_Mod::window_bits(exp.bits(), base.bits(), hints);

   g.resize((1 << window_bits));

   SecureVector<word> z(2 * (mod_words + 1));
   SecureVector<word> workspace(z.size());

   g[0] = 1;

   bigint_monty_mul(&z[0], z.size(),
                    g[0].data(), g[0].size(), g[0].sig_words(),
                    R2.data(), R2.size(), R2.sig_words(),
                    modulus.data(), mod_words, mod_prime,
                    &workspace[0]);

   g[0].assign(&z[0], mod_words + 1);

   g[1] = (base >= modulus) ? (base % modulus) : base;

   bigint_monty_mul(&z[0], z.size(),
                    g[1].data(), g[1].size(), g[1].sig_words(),
                    R2.data(), R2.size(), R2.sig_words(),
                    modulus.data(), mod_words, mod_prime,
                    &workspace[0]);

   g[1].assign(&z[0], mod_words + 1);

   const BigInt& x = g[1];
   const size_t x_sig = x.sig_words();

   for(size_t i = 1; i != g.size(); ++i)
      {
      const BigInt& y = g[i-1];
      const size_t y_sig = y.sig_words();

      zeroise(z);
      bigint_monty_mul(&z[0], z.size(),
                       x.data(), x.size(), x_sig,
                       y.data(), y.size(), y_sig,
                       modulus.data(), mod_words, mod_prime,
                       &workspace[0]);

      g[i].assign(&z[0], mod_words + 1);
      }
   }

/*
* Compute the result
*/
BigInt Montgomery_Exponentiator::execute() const
   {
   const size_t exp_nibbles = (exp_bits + window_bits - 1) / window_bits;

   BigInt x = R_mod;
   SecureVector<word> z(2 * (mod_words + 1));
   SecureVector<word> workspace(2 * (mod_words + 1));

   for(size_t i = exp_nibbles; i > 0; --i)
      {
      for(size_t k = 0; k != window_bits; ++k)
         {
         zeroise(z);

         bigint_monty_sqr(&z[0], z.size(),
                          x.data(), x.size(), x.sig_words(),
                          modulus.data(), mod_words, mod_prime,
                          &workspace[0]);

         x.assign(&z[0], mod_words + 1);
         }

      const u32bit nibble = exp.get_substring(window_bits*(i-1), window_bits);

      const BigInt& y = g[nibble];

      zeroise(z);
      bigint_monty_mul(&z[0], z.size(),
                       x.data(), x.size(), x.sig_words(),
                       y.data(), y.size(), y.sig_words(),
                       modulus.data(), mod_words, mod_prime,
                       &workspace[0]);

      x.assign(&z[0], mod_words + 1);
      }

   x.get_reg().resize(2*mod_words+1);

   bigint_monty_redc(&x[0], x.size(),
                     modulus.data(), mod_words, mod_prime,
                     &workspace[0]);

   x.get_reg().resize(mod_words+1);

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

   window_bits = 0;
   this->hints = hints;
   modulus = mod;
   exp_bits = 0;

   mod_words = modulus.sig_words();

   BigInt r(BigInt::Power2, mod_words * BOTAN_MP_WORD_BITS);
   mod_prime = (((r * inverse_mod(r, mod)) - 1) / mod).word_at(0);

   R_mod = r % modulus;

   R2 = (R_mod * R_mod) % modulus;
   }

}
