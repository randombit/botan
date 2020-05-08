/*
* RDRAND RNG
* (C) 2016,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rdrand_rng.h>
#include <botan/processor_rng.h>
#include <botan/loadstor.h>

namespace Botan {

void RDRAND_RNG::randomize(uint8_t out[], size_t out_len)
   {
   Processor_RNG rng;
   rng.randomize(out, out_len);
   }

RDRAND_RNG::RDRAND_RNG()
   {
   // Will throw if instruction is not available
   Processor_RNG rng;
   }

//static
bool RDRAND_RNG::available()
   {
   return Processor_RNG::available();
   }

//static
uint32_t RDRAND_RNG::rdrand()
   {
   Processor_RNG rng;

   for(;;)
      {
      try
         {
         uint8_t out[4];
         rng.randomize(out, 4);
         return load_le<uint32_t>(out, 0);
         }
      catch(PRNG_Unseeded&) {}
      }
   }

//static
uint32_t RDRAND_RNG::rdrand_status(bool& ok)
   {
   ok = false;
   Processor_RNG rng;

   try
      {
      uint8_t out[4];
      rng.randomize(out, 4);
      ok = true;
      return load_le<uint32_t>(out, 0);
      }
   catch(PRNG_Unseeded&) {}

   return 0;
   }

}
