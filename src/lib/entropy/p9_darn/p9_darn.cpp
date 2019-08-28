/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/p9_darn.h>
#include <botan/cpuid.h>

namespace Botan {

namespace {

bool read_darn(secure_vector<uint64_t>& seed)
   {
   const size_t DARN_RETRIES = 512;

   for(size_t i = 0; i != DARN_RETRIES; ++i)
      {
      uint64_t r = 0;

      // DARN 0: 32-bit conditioned, 1: 64-bit condition, 2: 64-bit raw (ala RDSEED)
      asm volatile("darn %0, 2" : "=r" (r));

      // DARN indicates error by 0xFF..FF, ie is biased (!?!?)
      if((~r) != 0)
         {
         seed.push_back(r);
         return true;
         }
      }

   return false; // failed to produce an output after many attempts
   }

}

size_t POWER9_DARN::poll(RandomNumberGenerator& rng)
   {
   const size_t DARN_BYTES = 1024;
   static_assert(DARN_BYTES % 8 == 0, "Bad DARN configuration");

   if(CPUID::has_darn_rng())
      {
      secure_vector<uint64_t> seed;
      seed.reserve(DARN_BYTES / 8);

      for(size_t p = 0; p != DARN_BYTES / 8; ++p)
         {
         if(!read_darn(seed))
            break;
         }

      if(seed.size() > 0)
         {
         rng.add_entropy(reinterpret_cast<const uint8_t*>(seed.data()),
                         seed.size() * sizeof(uint32_t));
         }
      }

   // DARN is used but not trusted
   return 0;
   }

}
