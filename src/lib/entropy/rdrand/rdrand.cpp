/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012,2015 Jack Lloyd
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
   Don't consider rdrand as contributing any entropy to the poll. It doesn't
   make sense to trust uninspectible hardware.

   Even if backdoored, rdrand cannot harm us because the HMAC_RNG poll process
   is designed to handle arbitrarily large amounts of attacker known/chosen
   input (or even a reseed where every bit we reseeded with was attacker chosen),
   as long as at least one seed occurred with enough unknown-to-attacker entropy.
   */
   const double ENTROPY_ESTIMATE = 0.0;
   const size_t RDRAND_POLLS = 32;

   for(size_t i = 0; i != RDRAND_POLLS; ++i)
      {
      unsigned int r = 0;

#if defined(BOTAN_USE_GCC_INLINE_ASM)
      int cf = 0;

      // Encoding of rdrand %eax
      asm(".byte 0x0F, 0xC7, 0xF0; adcl $0,%1" :
          "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");
#else
      int cf = _rdrand32_step(&r);
#endif

      if(cf == 1)
         accum.add(r, ENTROPY_ESTIMATE);
      }
   }

}
