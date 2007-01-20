/*************************************************
* BigInt Random Generation Source File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/bigint.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/rng.h>

namespace Botan {

/*************************************************
* Construct a BigInt of a specific form          *
*************************************************/
BigInt::BigInt(NumberType type, u32bit bits)
   {
   set_sign(Positive);
   if(type == Random && bits)
      randomize(bits);
   else if(type == Power2)
      set_bit(bits);
   else
      throw Invalid_Argument("BigInt(NumberType): Unknown type");
   }

/*************************************************
* Randomize this number                          *
*************************************************/
void BigInt::randomize(u32bit bitsize)
   {
   set_sign(Positive);

   if(bitsize == 0)
      clear();
   else
      {
      SecureVector<byte> array((bitsize + 7) / 8);
      Global_RNG::randomize(array, array.size());
      if(bitsize % 8)
         array[0] &= 0xFF >> (8 - (bitsize % 8));
      array[0] |= 0x80 >> ((bitsize % 8) ? (8 - bitsize % 8) : 0);
      binary_decode(array, array.size());
      }
   }

/*************************************************
* Generate a random integer                      *
*************************************************/
BigInt random_integer(u32bit bits)
   {
   BigInt x;
   x.randomize(bits);
   return x;
   }

/*************************************************
* Generate a random integer within given range   *
*************************************************/
BigInt random_integer(const BigInt& min, const BigInt& max)
   {
   BigInt range = max - min;

   if(range <= 0)
      throw Invalid_Argument("random_integer: invalid min/max values");

   return (min + (random_integer(range.bits() + 2) % range));
   }

/*************************************************
* Generate a random safe prime                   *
*************************************************/
BigInt random_safe_prime(u32bit bits)
   {
   if(bits <= 64)
      throw Invalid_Argument("random_safe_prime: Can't make a prime of " +
                             to_string(bits) + " bits");

   BigInt p;
   do
      p = (random_prime(bits - 1) << 1) + 1;
   while(!is_prime(p));
   return p;
   }

}
