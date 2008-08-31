#include <botan/botan.h>
using namespace Botan;

#include "common.h"
#include <time.h>

/*
  Using clock() or similiar is bad news when using a hardware-based Engine,
  as all the stuff is offloaded and we use zero CPU time, which makes the
  benchmarks and such take forever.
*/

#define USE_CLOCK         0
#define USE_TIMES         0
#define USE_POSIX_GETTIME 0
#define USE_RDTSC         1

/* If using USE_RDTSC, set to your CPU's Mhz */
#define CPU_MHZ 2400

#if USE_CLOCK

   u64bit get_clock() { return clock(); }
   u64bit get_ticks() { return CLOCKS_PER_SEC; }

#elif USE_TIMES

  #include <sys/times.h>
  #include <unistd.h>
  u64bit get_clock() { return times(0); }
  u64bit get_ticks() { return sysconf(_SC_CLK_TCK); }

#elif USE_POSIX_GETTIME

u64bit get_clock()
   {
   struct timespec tv;
   clock_gettime(CLOCK_REALTIME, &tv);

   return (tv.tv_sec * 1000000000 + tv.tv_nsec) / 1000;
   }

u64bit get_ticks() { return 1000000; }
#elif USE_RDTSC

  u64bit get_clock()
     {
     u64bit rtc = 0;
     u32bit rtc_low = 0, rtc_high = 0;
     asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
     rtc = ((u64bit)rtc_high << 32) | rtc_low;
     return rtc / 1000;
     }

  u64bit get_ticks() { return CPU_MHZ * 1000; }
#else
  #error "Must choose a timing method!"
#endif
