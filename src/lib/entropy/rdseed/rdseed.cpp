/*
* Entropy Source Using Intel's rdseed instruction
* (C) 2015 Jack Lloyd, Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rdseed.h>
#include <botan/cpuid.h>

#if !defined(BOTAN_USE_GCC_INLINE_ASM)
  #include <immintrin.h>
#endif

namespace Botan {

/*
* Get the timestamp
*/
void Intel_Rdseed::poll(Entropy_Accumulator& accum)
   {
   if(!CPUID::has_rdseed())
      return;

   const size_t RDSEED_POLLS = 32;

   for(size_t i = 0; i != RDSEED_POLLS; ++i)
      {
      unsigned int r = 0;

#if defined(BOTAN_USE_GCC_INLINE_ASM)
      int cf = 0;

      // Encoding of rdseed %eax
      asm(".byte 0x0F, 0xC7, 0xF8; adcl $0,%1" :
          "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");
#else
      int cf = _rdseed32_step(&r);
#endif

      if(cf == 1)
         accum.add(r, BOTAN_ENTROPY_ESTIMATE_HARDWARE_RNG);
      }
   }

}
