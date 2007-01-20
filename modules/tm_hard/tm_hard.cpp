/*************************************************
* Hardware Timer Source File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/tm_hard.h>
#include <botan/config.h>

namespace Botan {

/*************************************************
* Get the timestamp                              *
*************************************************/
u64bit Hardware_Timer::clock() const
   {
   u64bit rtc = 0;

#if defined(BOTAN_TARGET_ARCH_IS_IA32) || defined(BOTAN_TARGET_ARCH_IS_AMD64)
   u32bit rtc_low = 0, rtc_high = 0;
   asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
   rtc = ((u64bit)rtc_high << 32) | rtc_low;
#elif defined(BOTAN_TARGET_ARCH_IS_PPC) || defined(BOTAN_TARGET_ARCH_IS_PPC64)
   u32bit rtc_low = 0, rtc_high = 0;
   asm volatile("mftbu %0; mftb %1" : "=r" (rtc_high), "=r" (rtc_low));
   rtc = ((u64bit)rtc_high << 32) | rtc_low;
#elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r" (rtc));
#elif defined(BOTAN_TARGET_ARCH_IS_SPARC64)
   asm volatile("rd %%tick, %0" : "=r" (rtc));
#else
   #error "Unsure how to access hardware timer on this system"
#endif

   return rtc;
   }

}
