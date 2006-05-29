/*************************************************
* Montgomery Exponentiation Source File          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/def_powm.h>
#include <botan/numthry.h>
#include <botan/mp_core.h>

namespace Botan {

namespace {

/*************************************************
* Try to choose a good window size               *
*************************************************/
u32bit choose_window_bits(u32bit exp_bits, u32bit,
                          Power_Mod::Usage_Hints hints)
   {
   static const u32bit wsize[][2] = {
      { 2048, 4 }, { 1024, 3 }, { 256, 2 }, { 128, 1 }, { 0, 0 }
   };

   u32bit window_bits = 1;

   if(exp_bits)
      {
      for(u32bit j = 0; wsize[j][0]; ++j)
         {
         if(exp_bits >= wsize[j][0])
            {
            window_bits += wsize[j][1];
            break;
            }
         }
      }

   if(hints & Power_Mod::BASE_IS_FIXED)
      window_bits += 2;
   if(hints & Power_Mod::EXP_IS_LARGE)
      ++window_bits;

   return window_bits;
   }

}

/*************************************************
* Set the exponent                               *
*************************************************/
void Montgomery_Exponentiator::set_exponent(const BigInt& exp)
   {
   this->exp = exp;
   exp_bits = exp.bits();
   }

/*************************************************
* Set the base                                   *
*************************************************/
void Montgomery_Exponentiator::set_base(const BigInt& base)
   {
   window_bits = choose_window_bits(exp.bits(), base.bits(), hints);

   g.resize((1 << window_bits) - 1);

   SecureVector<word> z(2 * (mod_words + 1));
   SecureVector<word> workspace(z.size());

   g[0] = (base >= modulus) ? (base % modulus) : base;
   bigint_mul(z.begin(), z.size(), workspace,
              g[0].data(), g[0].size(), g[0].sig_words(),
              R2.data(), R2.size(), R2.sig_words());

   montgomery_reduce(z.begin(), z.size(), modulus.data(), mod_words,
                     mod_prime);
   g[0].get_reg().set(z + mod_words, mod_words + 1);

   const BigInt& x = g[0];
   const u32bit x_sig = x.sig_words();

   for(u32bit j = 1; j != g.size(); ++j)
      {
      const BigInt& y = g[j-1];
      const u32bit y_sig = y.sig_words();

      z.clear();
      bigint_mul(z.begin(), z.size(), workspace,
                 x.data(), x.size(), x_sig,
                 y.data(), y.size(), y_sig);

      montgomery_reduce(z.begin(), z.size(), modulus.data(), mod_words,
                        mod_prime);

      g[j].get_reg().set(z + mod_words, mod_words + 1);
      }
   }

/*************************************************
* Compute the result                             *
*************************************************/
BigInt Montgomery_Exponentiator::execute() const
   {
   const u32bit exp_nibbles = (exp_bits + window_bits - 1) / window_bits;

   BigInt x = R_mod;
   SecureVector<word> z(2 * (mod_words + 1));
   SecureVector<word> workspace(2 * (mod_words + 1));

   for(u32bit j = exp_nibbles; j > 0; --j)
      {
      for(u32bit k = 0; k != window_bits; ++k)
         {
         z.clear();
         bigint_sqr(z.begin(), z.size(), workspace,
                    x.data(), x.size(), x.sig_words());

         montgomery_reduce(z.begin(), z.size(), modulus.data(), mod_words,
                           mod_prime);
         x.get_reg().set(z + mod_words, mod_words + 1);
         }

      u32bit nibble = exp.get_substring(window_bits*(j-1), window_bits);
      if(nibble)
         {
         const BigInt& y = g[nibble-1];

         z.clear();
         bigint_mul(z.begin(), z.size(), workspace,
                    x.data(), x.size(), x.sig_words(),
                    y.data(), y.size(), y.sig_words());

         montgomery_reduce(z.begin(), z.size(), modulus.data(), mod_words,
                           mod_prime);
         x.get_reg().set(z + mod_words, mod_words + 1);
         }
      }

   z.clear();
   z.copy(x.data(), x.size());

   montgomery_reduce(z.begin(), z.size(), modulus.data(), mod_words,
                     mod_prime);
   x.get_reg().set(z + mod_words, mod_words + 1);
   return x;
   }

/*************************************************
* Montgomery_Exponentiator Constructor           *
*************************************************/
Montgomery_Exponentiator::Montgomery_Exponentiator(const BigInt& mod,
   Power_Mod::Usage_Hints hints)
   {
   if(!mod.is_positive())
      throw Exception("Montgomery_Exponentiator: modulus must be positive");
   if(mod.is_even())
      throw Exception("Montgomery_Exponentiator: modulus must be odd");

   window_bits = 0;
   this->hints = hints;
   modulus = mod;

   mod_words = modulus.sig_words();

   BigInt mod_prime_bn(BigInt::Power2, MP_WORD_BITS);
   mod_prime = (mod_prime_bn - inverse_mod(modulus, mod_prime_bn)).word_at(0);

   R_mod = BigInt(BigInt::Power2, MP_WORD_BITS * mod_words);
   R_mod %= modulus;

   R2 = BigInt(BigInt::Power2, 2 * MP_WORD_BITS * mod_words);
   R2 %= modulus;
   }

}
