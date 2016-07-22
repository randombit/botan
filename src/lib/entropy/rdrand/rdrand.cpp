/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012,2015 Jack Lloyd
* (C) 2015 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rdrand.h>
#include <botan/rdrand_rng.h>
#include <botan/cpuid.h>
#include <botan/build.h>

namespace Botan {

size_t Intel_Rdrand::poll(RandomNumberGenerator& rng) {
   if(CPUID::has_rdrand() && BOTAN_ENTROPY_INTEL_RNG_POLLS > 0)
      {
      RDRAND_RNG rdrand_rng;
      secure_vector<uint8_t> buf(4 * BOTAN_ENTROPY_INTEL_RNG_POLLS);

      rdrand_rng.randomize(buf.data(), buf.size());
      rng.add_entropy(buf.data(), buf.size());
      }

   // RDRAND is used but not trusted
   return 0;
   }

}
