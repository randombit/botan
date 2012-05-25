/*
* Runtime CPU detection
* (C) 2009-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CPUID_H__
#define BOTAN_CPUID_H__

#include <botan/types.h>

namespace Botan {

/**
* A class handling runtime CPU feature detection
*/
class BOTAN_DLL CPUID
   {
   public:
      /**
      * Probe the CPU and see what extensions are supported
      */
      static void initialize();

      /**
      * Return a best guess of the cache line size
      */
      static size_t cache_line_size() { return cache_line; }

      /**
      * Check if the processor supports RDTSC
      */
      static bool has_rdtsc()
         { return x86_processor_flags_has(CPUID_RDTSC_BIT); }

      /**
      * Check if the processor supports SSE2
      */
      static bool has_sse2()
         { return x86_processor_flags_has(CPUID_SSE2_BIT); }

      /**
      * Check if the processor supports SSSE3
      */
      static bool has_ssse3()
         { return x86_processor_flags_has(CPUID_SSSE3_BIT); }

      /**
      * Check if the processor supports SSE4.1
      */
      static bool has_sse41()
         { return x86_processor_flags_has(CPUID_SSE41_BIT); }

      /**
      * Check if the processor supports SSE4.2
      */
      static bool has_sse42()
         { return x86_processor_flags_has(CPUID_SSE42_BIT); }

      /**
      * Check if the processor supports extended AVX vector instructions
      */
      static bool has_avx()
         { return x86_processor_flags_has(CPUID_AVX_BIT); }

      /**
      * Check if the processor supports AES-NI
      */
      static bool has_aes_ni()
         { return x86_processor_flags_has(CPUID_AESNI_BIT); }

      /**
      * Check if the processor supports PCMULUDQ
      */
      static bool has_pcmuludq()
         { return x86_processor_flags_has(CPUID_PCMUL_BIT); }

      /**
      * Check if the processor supports MOVBE
      */
      static bool has_movbe()
         { return x86_processor_flags_has(CPUID_MOVBE_BIT); }

      /**
      * Check if the processor supports RDRAND
      */
      static bool has_rdrand()
         { return x86_processor_flags_has(CPUID_RDRAND_BIT); }

      /**
      * Check if the processor supports AltiVec/VMX
      */
      static bool has_altivec() { return altivec_capable; }
   private:
      enum CPUID_bits {
         CPUID_RDTSC_BIT = 4,
         CPUID_SSE2_BIT = 26,
         CPUID_PCMUL_BIT = 33,
         CPUID_SSSE3_BIT = 41,
         CPUID_SSE41_BIT = 51,
         CPUID_SSE42_BIT = 52,
         CPUID_MOVBE_BIT = 54,
         CPUID_AESNI_BIT = 57,
         CPUID_AVX_BIT = 60,
         CPUID_RDRAND_BIT = 62
      };

      static bool x86_processor_flags_has(u64bit bit)
         {
         return ((x86_processor_flags >> bit) & 1);
         }

      static u64bit x86_processor_flags;
      static size_t cache_line;
      static bool altivec_capable;
   };

}

#endif
