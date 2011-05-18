/*
* Modular Reducer
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
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

   modulus = mod;
   mod_words = modulus.sig_words();

   modulus_2 = Botan::square(modulus);

   mu = BigInt(BigInt::Power2, 2 * MP_WORD_BITS * mod_words) / modulus;
   }

/*
* Barrett Reduction
*/
BigInt Modular_Reducer::reduce(const BigInt& x) const
   {
   if(mod_words == 0)
      throw Invalid_State("Modular_Reducer: Never initalized");

   if(x.cmp(modulus, false) < 0)
      {
      if(x.is_negative())
         return x + modulus; // make positive
      return x;
      }
   else if(x.cmp(modulus_2, false) < 0)
      {
      BigInt t1 = x;
      t1.set_sign(BigInt::Positive);
      t1 >>= (MP_WORD_BITS * (mod_words - 1));
      t1 *= mu;

      t1 >>= (MP_WORD_BITS * (mod_words + 1));
      t1 *= modulus;

      t1.mask_bits(MP_WORD_BITS * (mod_words + 1));

      BigInt t2 = x;
      t2.set_sign(BigInt::Positive);
      t2.mask_bits(MP_WORD_BITS * (mod_words + 1));

      t2 -= t1;

      if(t2.is_negative())
         {
         BigInt b_to_k1(BigInt::Power2, MP_WORD_BITS * (mod_words + 1));
         t2 += b_to_k1;
         }

      while(t2 >= modulus)
         t2 -= modulus;

      if(x.is_positive())
         return t2;
      else
         return (modulus - t2);
      }
   else
      {
      // too big, fall back to normal division
      return (x % modulus);
      }
   }

}
