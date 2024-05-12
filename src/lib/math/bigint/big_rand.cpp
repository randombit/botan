/*
* BigInt Random Generation
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bigint.h>

#include <botan/rng.h>
#include <botan/internal/rounding.h>

namespace Botan {

/*
* Randomize this number
*/
void BigInt::randomize(RandomNumberGenerator& rng, size_t bitsize, bool set_high_bit) {
   set_sign(Positive);

   if(bitsize == 0) {
      clear();
   } else {
      secure_vector<uint8_t> array = rng.random_vec(round_up(bitsize, 8) / 8);

      // Always cut unwanted bits
      if(bitsize % 8) {
         array[0] &= 0xFF >> (8 - (bitsize % 8));
      }

      // Set the highest bit if wanted
      if(set_high_bit) {
         array[0] |= 0x80 >> ((bitsize % 8) ? (8 - bitsize % 8) : 0);
      }

      assign_from_bytes(array);
   }
}

/*
* Generate a random integer within given range
*/
BigInt BigInt::random_integer(RandomNumberGenerator& rng, const BigInt& min, const BigInt& max) {
   if(min.is_negative() || max.is_negative() || max <= min) {
      throw Invalid_Argument("BigInt::random_integer invalid range");
   }

   /*
   If min is > 1 then we generate a random number `r` in [0,max-min)
   and return min + r.

   This same logic could also be reasonbly chosen for min == 1, but
   that breaks certain tests which expect stability of this function
   when generating within [1,n)
   */
   if(min > 1) {
      const BigInt diff = max - min;
      // This call is recursive, but will not recurse further
      return min + BigInt::random_integer(rng, BigInt::zero(), diff);
   }

   BOTAN_DEBUG_ASSERT(min <= 1);

   const size_t bits = max.bits();

   BigInt r;

   do {
      r.randomize(rng, bits, false);
   } while(r < min || r >= max);

   return r;
}

}  // namespace Botan
