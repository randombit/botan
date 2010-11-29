/*
* Runtime CPU detection
* (C) 2009-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cpuid.h>
#include <botan/types.h>
#include <botan/get_byte.h>
#include <botan/mem_ops.h>

#if defined(BOTAN_TARGET_OS_IS_DARWIN)
  #include <sys/sysctl.h>
#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)

  #include <intrin.h>
  #define CALL_CPUID(type, out) do { __cpuid((int*)out, type); } while(0)

#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)

  #include <ia32intrin.h>
  #define CALL_CPUID(type, out) do { __cpuid(out, type); } while(0);

#elif (BOTAN_GCC_VERSION >= 430) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)

  // Only available starting in GCC 4.3
  #include <cpuid.h>
  #define CALL_CPUID(type, out) \
    do { __get_cpuid(type, out, out+1, out+2, out+3); } while(0);

#else
  #warning "No method of calling CPUID for this compiler"
#endif

#endif

#ifndef CALL_CPUID
  // In all other cases, just zeroize the supposed cpuid output
  #define CALL_CPUID(type, out) \
    do { out[0] = out[1] = out[2] = out[3] = 0; } while(0);
#endif

namespace Botan {

u64bit CPUID::x86_processor_flags = 0;
size_t CPUID::cache_line = 32;
bool CPUID::altivec_capable = false;

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

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

bool altivec_check_sysctl()
   {
#if defined(BOTAN_TARGET_OS_IS_DARWIN)

   // From Apple's docs
   int sels[2] = { CTL_HW, HW_VECTORUNIT };
   int vector_type = 0;
   size_t length = sizeof(vector_type);
   int error = sysctl(sels, 2, &vector_type, &length, NULL, 0);

   if(error == 0 && vector_type > 0)
      return true;
#endif

   return false;
   }

bool altivec_check_pvr_emul()
   {
   bool altivec_capable = false;

#if defined(BOTAN_TARGET_OS_IS_LINUX) || defined(BOTAN_TARGET_OS_IS_NETBSD)

   /*
   On PowerPC, MSR 287 is PVR, the Processor Version Number
   Normally it is only accessible to ring 0, but Linux and NetBSD
   (others, too, maybe?) will trap and emulate it for us.

   PVR identifiers for various AltiVec enabled CPUs. Taken from
   PearPC and Linux sources, mostly.
   */

   const u16bit PVR_G4_7400  = 0x000C;
   const u16bit PVR_G5_970   = 0x0039;
   const u16bit PVR_G5_970FX = 0x003C;
   const u16bit PVR_G5_970MP = 0x0044;
   const u16bit PVR_G5_970GX = 0x0045;
   const u16bit PVR_POWER6   = 0x003E;
   const u16bit PVR_CELL_PPU = 0x0070;

   // Motorola produced G4s with PVR 0x800[0123C] (at least)
   const u16bit PVR_G4_74xx_24  = 0x800;

   u32bit pvr = 0;

   asm volatile("mfspr %0, 287" : "=r" (pvr));

   // Top 16 bit suffice to identify model
   pvr >>= 16;

   altivec_capable |= (pvr == PVR_G4_7400);
   altivec_capable |= ((pvr >> 4) == PVR_G4_74xx_24);
   altivec_capable |= (pvr == PVR_G5_970);
   altivec_capable |= (pvr == PVR_G5_970FX);
   altivec_capable |= (pvr == PVR_G5_970MP);
   altivec_capable |= (pvr == PVR_G5_970GX);
   altivec_capable |= (pvr == PVR_POWER6);
   altivec_capable |= (pvr == PVR_CELL_PPU);
#endif

   return altivec_capable;
   }

#endif

}

void CPUID::initialize()
   {
   u32bit cpuid[4] = { 0 };
   CALL_CPUID(1, cpuid);

   x86_processor_flags = ((u64bit)cpuid[2] << 32) | cpuid[3];

#if defined(BOTAN_TARGET_ARCH_IS_AMD64)
   /*
   * If we don't have access to CPUID, we can still safely assume that
   * any x86-64 processor has SSE2.
   */
   if(x86_processor_flags == 0)
     x86_processor_flags |= (1 << CPUID_SSE2_BIT);
#endif

   cache_line = get_x86_cache_line_size();

   altivec_capable = false;

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
      if(altivec_check_sysctl() || altivec_check_pvr_emul())
         altivec_capable = true;
#endif
   }

}
