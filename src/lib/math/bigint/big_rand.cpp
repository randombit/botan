/*
* BigInt Random Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>
#include <botan/parsing.h>

namespace Botan {

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
      secure_vector<byte> array = rng.random_vec((bitsize + 7) / 8);

      if(bitsize % 8)
         array[0] &= 0xFF >> (8 - (bitsize % 8));
      array[0] |= 0x80 >> ((bitsize % 8) ? (8 - bitsize % 8) : 0);
      binary_decode(array.data(), array.size());
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
