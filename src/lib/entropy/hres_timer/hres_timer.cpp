/*
* High Resolution Timestamp Entropy Source
* (C) 1999-2009,2011,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hres_timer.h>
#include <botan/cpuid.h>
#include <chrono>

#if defined(BOTAN_TARGET_OS_HAS_QUERY_PERF_COUNTER)
  #include <windows.h>
  #undef min
  #undef max
#endif

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
  #include <time.h>
#endif

namespace Botan {

/*
* Get the timestamp
*/
void High_Resolution_Timestamp::poll(Entropy_Accumulator& accum)
   {
   // Don't count any timestamps as contributing any entropy
   const double ESTIMATED_ENTROPY_PER_BYTE = 0.0;

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

#define CLOCK_GETTIME_POLL(src)                              \
   do {                                                      \
     struct timespec ts;                                     \
     ::clock_gettime(src, &ts);                              \
     accum.add(&ts, sizeof(ts), ESTIMATED_ENTROPY_PER_BYTE); \
   } while(0)

#if defined(CLOCK_REALTIME)
   CLOCK_GETTIME_POLL(CLOCK_REALTIME);
#endif

#if defined(CLOCK_MONOTONIC)
   CLOCK_GETTIME_POLL(CLOCK_MONOTONIC);
#endif

#if defined(CLOCK_MONOTONIC_RAW)
   CLOCK_GETTIME_POLL(CLOCK_MONOTONIC_RAW);
#endif

#if defined(CLOCK_PROCESS_CPUTIME_ID)
   CLOCK_GETTIME_POLL(CLOCK_PROCESS_CPUTIME_ID);
#endif

#if defined(CLOCK_THREAD_CPUTIME_ID)
   CLOCK_GETTIME_POLL(CLOCK_THREAD_CPUTIME_ID);
#endif

#undef CLOCK_GETTIME_POLL

#else

#define STD_CHRONO_POLL(clock)                                  \
   do {                                                         \
      auto timestamp = clock::now().time_since_epoch().count(); \
      accum.add(timestamp, ESTIMATED_ENTROPY_PER_BYTE);         \
   } while(0)

  STD_CHRONO_POLL(std::chrono::high_resolution_clock);
  STD_CHRONO_POLL(std::chrono::system_clock);

#undef STD_CHRONO_POLL

#endif

#if BOTAN_USE_GCC_INLINE_ASM

   u64bit rtc = 0;

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(CPUID::has_rdtsc()) // not availble on all x86 CPUs
      {
      u32bit rtc_low = 0, rtc_high = 0;
      asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
      rtc = (static_cast<u64bit>(rtc_high) << 32) | rtc_low;
      }

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   u32bit rtc_low = 0, rtc_high = 0;
   asm volatile("mftbu %0; mftb %1" : "=r" (rtc_high), "=r" (rtc_low));
   rtc = (static_cast<u64bit>(rtc_high) << 32) | rtc_low;

#elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_SPARC64) && !defined(BOTAN_TARGET_OS_IS_OPENBSD)
   asm volatile("rd %%tick, %0" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_IA64)
   asm volatile("mov %0=ar.itc" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_S390X)
   asm volatile("stck 0(%0)" : : "a" (&rtc) : "memory", "cc");

#elif defined(BOTAN_TARGET_ARCH_IS_HPPA)
   asm volatile("mfctl 16,%0" : "=r" (rtc)); // 64-bit only?

#endif

   accum.add(rtc, ESTIMATED_ENTROPY_PER_BYTE);

#endif

#if defined(BOTAN_TARGET_OS_HAS_QUERY_PERF_COUNTER)
   {
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   accum.add(tv.QuadPart, ESTIMATED_ENTROPY_PER_BYTE);
   }
#endif
   }

}
