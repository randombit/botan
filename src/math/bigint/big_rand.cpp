/*
* BigInt Random Generation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/bigint.h>
#include <botan/parsing.h>

namespace Botan {

/*
* Construct a BigInt of a specific form
*/
BigInt::BigInt(NumberType type, size_t bits)
   {
   set_sign(Positive);

   if(type == Power2)
      set_bit(bits);
   else
      throw Invalid_Argument("BigInt(NumberType): Unknown type");
   }

/*
* Randomize this number
*/
void BigInt::randomize(RandomNumberGenerator& rng,
                       size_t bitsize)
   {
   set_sign(Positive);

   if(bitsize == 0)
      clear();
   else
      {
      SecureVector<byte> array = rng.random_vec((bitsize + 7) / 8);

      if(bitsize % 8)
         array[0] &= 0xFF >> (8 - (bitsize % 8));
      array[0] |= 0x80 >> ((bitsize % 8) ? (8 - bitsize % 8) : 0);
      binary_decode(&array[0], array.size());
      }
   }

/*
* Generate a random integer within given range
*/
BigInt BigInt::random_integer(RandomNumberGenerator& rng,
                              const BigInt& min, const BigInt& max)
   {
   BigInt range = max - min;

   if(range <= 0)
      throw Invalid_Argument("random_integer: invalid min/max values");

   return (min + (BigInt(rng, range.bits() + 2) % range));
   }

}
