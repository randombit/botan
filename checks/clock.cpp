#include "timer.h"
#include <botan/build.h>

#define USE_CLOCK_GETTIME 1
#define USE_GETTIMEOFDAY 0
#define USE_TIMES 0
#define USE_CLOCK 0

#if USE_CLOCK_GETTIME
  #include <time.h>
#elif USE_GETTIMEOFDAY
  #include <sys/time.h>
#elif USE_TIMES
  #include <sys/times.h>
  #include <unistd.h>
#elif USE_CLOCK
  #include <time.h>
#endif

u64bit Timer::get_clock()
   {
   static const u64bit billion = 1000000000;

#if USE_CLOCK_GETTIME
   struct timespec tv;
   clock_gettime(CLOCK_REALTIME, &tv);
   return (billion * tv.tv_sec + tv.tv_nsec);
#elif USE_GETTIMEOFDAY
   struct timeval tv;
   gettimeofday(&tv, 0);
   return (billion * tv.tv_sec + 1000 * tv.tv_usec);
#elif USE_TIMES

   struct tms tms;
   times(&tms);

   static const u64bit clocks_to_nanoseconds =
      (billion / sysconf(_SC_CLK_TCK));

   return (tms.tms_utime * clocks_to_nanoseconds);
#elif USE_CLOCK
   static const u64bit clocks_to_nanoseconds =
      (billion / CLOCKS_PER_SEC);

   return clock() * clocks_to_nanoseconds;
#endif
   }
