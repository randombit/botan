/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012,2015,2019 Jack Lloyd
* (C) 2015 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rdrand.h>
#include <botan/rdrand_rng.h>

namespace Botan {

size_t Intel_Rdrand::poll(RandomNumberGenerator& rng)
   {
   /*
   * Intel's documentation for RDRAND at
   * https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide
   * claims that software can guarantee a reseed event by polling enough data:
   * "There is an upper bound of 511 samples per seed in the implementation
   * where samples are 128 bits in size and can provide two 64-bit random
   * numbers each."
   *
   * By requesting 8192 bytes we are asking for 512 samples and thus are assured
   * that at some point in producing the output, at least one reseed of the
   * internal state will occur.
   *
   * The alternative approach is to "Iteratively execute 32 RDRAND invocations
   * with a 10 us wait period per iteration." however in practice this proves to
   * be about 20x slower, despite producing much less seed material.
   */
   const size_t RDRAND_POLL_BYTES = 8*1024;

   if(RDRAND_RNG::available())
      {
      RDRAND_RNG rdrand_rng;
      secure_vector<uint8_t> buf(RDRAND_POLL_BYTES);
      rdrand_rng.randomize(&buf[0], buf.size());
      rng.add_entropy(buf.data(), buf.size());
      }

   // RDRAND is used but not trusted
   return 0;
   }

}
