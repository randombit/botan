/**
* Runtime CPU detection
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CPUID_H__
#define BOTAN_CPUID_H__

#include <botan/types.h>

namespace Botan {

class CPUID
   {
   public:
      enum CPUID_bits {
         CPUID_RDTSC_BIT = 4,
         CPUID_SSE2_BIT = 26,
         CPUID_SSSE3_BIT = 41,
         CPUID_SSE41_BIT = 51,
         CPUID_SSE42_BIT = 52
      };

      /**
      * Return a best guess of the cache line size
      */
      static u32bit cache_line_size();

      /**
      * Check if the processor supports RDTSC
      */
      static bool has_rdtsc()
         { return ((x86_processor_flags() >> CPUID_RDTSC_BIT) & 1); }

      /**
      * Check if the processor supports SSE2
      */
      static bool has_sse2()
         { return ((x86_processor_flags() >> CPUID_SSE2_BIT) & 1); }

      /**
      * Check if the processor supports SSSE3
      */
      static bool has_ssse3()
         { return ((x86_processor_flags() >> CPUID_SSSE3_BIT) & 1); }

      /**
      * Check if the processor supports SSE4.1
      */
      static bool has_sse41()
         { return ((x86_processor_flags() >> CPUID_SSE41_BIT) & 1); }

      /**
      * Check if the processor supports SSE4.2
      */
      static bool has_sse42()
         { return ((x86_processor_flags() >> CPUID_SSE42_BIT) & 1); }

   private:
      static u64bit x86_processor_flags();
   };

}

#endif
