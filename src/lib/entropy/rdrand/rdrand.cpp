/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rdrand.h>
#include <botan/cpuid.h>

#if !defined(BOTAN_USE_GCC_INLINE_ASM)
  #include <immintrin.h>
#endif

namespace Botan {

/*
* Get the timestamp
*/
void Intel_Rdrand::poll(Entropy_Accumulator& accum)
   {
   if(!CPUID::has_rdrand())
      return;

   /*
   * Put an upper bound on the total entropy we're willing to claim
   * for any one polling of rdrand to prevent it from swamping our
   * poll. Internally, the rdrand system is a DRGB that reseeds at a
   * somewhat unpredictable rate (the current conditions are
   * documented, but that might not be true for different
   * implementations, eg on Haswell or a future AMD chip, so I don't
   * want to assume). This limit ensures we're going to poll at least
   * one other source so we have some diversity in our inputs.
   */

   const size_t POLL_UPPER_BOUND = 96;
   const size_t RDRAND_POLLS = 32;
   const double ENTROPY_PER_POLL =
      static_cast<double>(POLL_UPPER_BOUND) / (RDRAND_POLLS * 4);

   for(size_t i = 0; i != RDRAND_POLLS; ++i)
      {
      unsigned int r = 0;

#if BOTAN_USE_GCC_INLINE_ASM
      int cf = 0;

      // Encoding of rdrand %eax
      asm(".byte 0x0F, 0xC7, 0xF0; adcl $0,%1" :
          "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");
#else
      int cf = _rdrand32_step(&r);
#endif

      if(cf == 1)
         accum.add(r, ENTROPY_PER_POLL);
      }
   }

}
