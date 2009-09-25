/**
* Runtime CPU detection
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cpuid.h>
#include <botan/types.h>

#if defined(_MSC_VER)
  #include <intrin.h>
#endif

namespace Botan {

namespace CPUID {

namespace {

/*
* Call the x86 CPUID instruction and return the contents of ecx and
* edx, which contain the feature masks.
*/
u64bit x86_processor_flags()
   {
   static u64bit proc_flags = 0;

   if(proc_flags)
      return proc_flags;

#if defined(BOTAN_TARGET_ARCH_IS_X86) || defined(BOTAN_TARGET_ARCH_IS_AMD64)

#if defined(__GNUG__)

   u32bit a = 1, b = 0, c = 0, d = 0;

#if defined(__i386__) && defined(__PIC__)
   // ebx is used in PIC on 32-bit x86, so save and restore it
   asm("xchgl %%ebx, %1\n\t"
       "cpuid\n\t"
       "xchgl %%ebx, %1\n\t"
       : "=a" (a), "=r" (b), "=c" (c), "=d" (d) : "0" (a));
#else
   // if not PIC or in 64-bit mode, can smash ebx
   asm("cpuid" : "=a" (a), "=b" (b), "=c" (c), "=d" (d) : "0" (a));

#endif

   proc_flags = ((u64bit)c << 32) | d;

#elif defined(_MSC_VER)

   int cpuinfo[4] = { 0 };
   __cpuid(cpuinfo, 1);

   proc_flags = ((u64bit)cpuinfo[2] << 32) | cpuinfo[3];

#endif

#endif

   return proc_flags;
   }

enum CPUID_bits {
   CPUID_RDTSC_BIT = 4,
   CPUID_SSE2_BIT = 26,
   CPUID_SSSE3_BIT = 41,
   CPUID_SSE41_BIT = 51,
   CPUID_SSE42_BIT = 52
};

}

u32bit cache_line_size()
   {
   return 32; // FIXME!
   }

bool has_rdtsc()
   {
   return ((x86_processor_flags() >> CPUID_RDTSC_BIT) & 1);
   }

bool has_sse2()
   {
   return ((x86_processor_flags() >> CPUID_SSE2_BIT) & 1);
   }

bool has_ssse3()
   {
   return ((x86_processor_flags() >> CPUID_SSSE3_BIT) & 1);
   }

bool has_sse41()
   {
   return ((x86_processor_flags() >> CPUID_SSE41_BIT) & 1);
   }

bool has_sse42()
   {
   return ((x86_processor_flags() >> CPUID_SSE42_BIT) & 1);
   }

}

}
