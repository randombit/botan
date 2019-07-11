/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/p9_darn.h>
#include <botan/cpuid.h>

namespace Botan {

size_t POWER9_DARN::poll(RandomNumberGenerator& rng)
   {
   if(CPUID::has_darn_rng())
      {
      secure_vector<uint64_t> seed(64);

      for(size_t i = 0; i != seed.size(); ++i)
         seed[i] = __builtin_darn_raw();

      rng.add_entropy(reinterpret_cast<const uint8_t*>(seed.data()),
                      seed.size() * sizeof(uint64_t));
      }

   return 0;
   }

}
