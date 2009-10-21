/**
* Runtime CPU detection
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cpuid.h>
#include <botan/types.h>
#include <botan/loadstor.h>
#include <botan/mem_ops.h>

#if defined(BOTAN_TARGET_ARCH_IS_IA32) || defined(BOTAN_TARGET_ARCH_IS_AMD64)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)

  #include <intrin.h>
  #define CALL_CPUID(type, out) do { __cpuid(out, type) } while(0)

#elif defined(BOTAN_BUILD_COMPILER_IS_ICC)

  #include <ia32intrin.h>
  #define CALL_CPUID(type, out) do { __cpuid(out, type) } while(0);

#elif defined(BOTAN_BUILD_COMPILER_IS_GCC)

  #include <cpuid.h>
  #define CALL_CPUID(type, out) \
    do { __get_cpuid(type, out, out+1, out+2, out+3); } while(0);

#endif

#else
  // In all other cases, just zeroize the supposed cpuid output
  #define CALL_CPUID(type, out) out[0] = out[1] = out[2] = out[3] = 0;
#endif

namespace Botan {

namespace {

u32bit get_x86_cache_line_size()
   {
   const u32bit INTEL_CPUID[3] = { 0x756E6547, 0x6C65746E, 0x49656E69 };
   const u32bit AMD_CPUID[3] = { 0x68747541, 0x444D4163, 0x69746E65 };

   u32bit cpuid[4] = { 0 };
   CALL_CPUID(0, cpuid);

   if(same_mem(cpuid + 1, INTEL_CPUID, 3))
      {
      CALL_CPUID(1, cpuid);
      return 8 * get_byte(2, cpuid[1]);
      }
   else if(same_mem(cpuid + 1, AMD_CPUID, 3))
      {
      CALL_CPUID(0x80000005, cpuid);
      return get_byte(3, cpuid[2]);
      }
   else
      return 32; // default cache line guess
   }

}

/*
* Call the x86 CPUID instruction and return the contents of ecx and
* edx, which contain the feature masks.
*/
u64bit CPUID::x86_processor_flags()
   {
   static u64bit proc_flags = 0;

   if(proc_flags)
      return proc_flags;

   u32bit cpuid[4] = { 0 };
   CALL_CPUID(1, cpuid);

   // Set the FPU bit on to force caching in proc_flags
   proc_flags = ((u64bit)cpuid[2] << 32) | cpuid[3] | 1;

   return proc_flags;
   }

u32bit CPUID::cache_line_size()
   {
   static u32bit cl_size = 0;

   if(cl_size)
      return cl_size;

   cl_size = get_x86_cache_line_size();

   return cl_size;
   }

}
