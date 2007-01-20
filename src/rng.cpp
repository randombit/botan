/*************************************************
* Global RNG Source File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/rng.h>
#include <botan/libstate.h>

namespace Botan {

namespace Global_RNG {

/*************************************************
* Get random bits from the global RNG            *
*************************************************/
void randomize(byte output[], u32bit size)
   {
   global_state().randomize(output, size);
   }

/*************************************************
* Get random bits from the global RNG            *
*************************************************/
byte random()
   {
   byte ret = 0;
   randomize(&ret, 1);
   return ret;
   }

/*************************************************
* Add entropy to the global RNG                  *
*************************************************/
void add_entropy(const byte entropy[], u32bit size)
   {
   global_state().add_entropy(entropy, size);
   }

/*************************************************
* Add entropy to the global RNG                  *
*************************************************/
void add_entropy(EntropySource& src, bool slow_poll)
   {
   global_state().add_entropy(src, slow_poll);
   }

/*************************************************
* Add an EntropySource to the RNG seed list      *
*************************************************/
void add_es(EntropySource* src, bool last)
   {
   global_state().add_entropy_source(src, last);
   }

/*************************************************
* Seed the global RNG                            *
*************************************************/
u32bit seed(bool slow_poll, u32bit bits_to_get)
   {
   return global_state().seed_prng(slow_poll, bits_to_get);
   }

}

}
