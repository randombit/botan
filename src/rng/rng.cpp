/*************************************************
* Random Number Generator Base Source File       *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/rng.h>

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
  #include <botan/auto_rng.h>
#endif

namespace Botan {

/*************************************************
* Get a single random byte                       *
*************************************************/
byte RandomNumberGenerator::next_byte()
   {
   byte out;
   this->randomize(&out, 1);
   return out;
   }

/*************************************************
* Create and seed a new RNG object               *
*************************************************/
RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   return new AutoSeeded_RNG;
#endif

   throw Algorithm_Not_Found("RandomNumberGenerator::make_rng - no RNG found");
   }

}
