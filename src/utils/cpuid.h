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

class BOTAN_DLL CPUID
   {
   public:
      enum CPUID_bits {
         CPUID_RDTSC_BIT = 4,
         CPUID_SSE2_BIT = 26,
         CPUID_SSSE3_BIT = 41,
         CPUID_SSE41_BIT = 51,
         CPUID_SSE42_BIT = 52,
         CPUID_INTEL_AES_BIT = 57,
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

      /**
      * Check if the processor supports Intel's AES instructions
      */
      static bool has_aes_intel()
         { return ((x86_processor_flags() >> CPUID_INTEL_AES_BIT) & 1); }

      /**
      * Check if the processor supports VIA's AES instructions
      * (not implemented)
      */
      static bool has_aes_via() { return false; }

      /**
      * Check if the processor supports AltiVec/VMX
      */
      static bool has_altivec();
   private:
      static u64bit x86_processor_flags();
   };

}

#endif
