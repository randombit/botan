/*
* Modular Reducer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/reducer.h>
#include <botan/numthry.h>
#include <botan/mp_core.h>

namespace Botan {

/*
* Modular_Reducer Constructor
*/
Modular_Reducer::Modular_Reducer(const BigInt& mod)
   {
   if(mod <= 0)
      throw Invalid_Argument("Modular_Reducer: modulus must be positive");

   modulus = mod;
   mod_words = modulus.sig_words();

   modulus_2 = Botan::square(modulus);
   mod2_words = modulus_2.sig_words();

   mu = BigInt(BigInt::Power2, 2 * MP_WORD_BITS * mod_words) / modulus;
   mu_words = mu.sig_words();
   }

/*
* Barrett Reduction
*/
BigInt Modular_Reducer::reduce(const BigInt& x) const
   {
   if(mod_words == 0)
      throw Invalid_State("Modular_Reducer: Never initalized");

   BigInt t1 = x;
   t1.set_sign(BigInt::Positive);

   if(t1 < modulus)
      {
      if(x.is_negative() && t1.is_nonzero())
         return modulus - t1;
      return x;
      }

   if(t1 >= modulus_2)
      return (x % modulus);

   t1 >>= (MP_WORD_BITS * (mod_words - 1));
   t1 *= mu;
   t1 >>= (MP_WORD_BITS * (mod_words + 1));

   t1 *= modulus;
   t1.mask_bits(MP_WORD_BITS * (mod_words+1));

   BigInt t2 = x;
   t2.set_sign(BigInt::Positive);
   t2.mask_bits(MP_WORD_BITS * (mod_words+1));

   t1 = t2 - t1;

   if(t1.is_negative())
      {
      BigInt b_to_k1(BigInt::Power2, MP_WORD_BITS * (mod_words+1));
      t1 += b_to_k1;
      }

   while(t1 >= modulus)
      t1 -= modulus;

   if(x.is_negative() && t1.is_nonzero())
      t1 = modulus - t1;

   return t1;
   }

/*
* Multiply, followed by a reduction
*/
BigInt Modular_Reducer::multiply(const BigInt& x, const BigInt& y) const
   {
   return reduce(x * y);
   }

/*
* Square, followed by a reduction
*/
BigInt Modular_Reducer::square(const BigInt& x) const
   {
   return reduce(Botan::square(x));
   }

}
