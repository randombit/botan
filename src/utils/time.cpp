/*
* Time Functions
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/time.h>
#include <botan/exceptn.h>
#include <ctime>

#if defined(BOTAN_TARGET_OS_HAS_WIN32_GET_SYSTEMTIME)
  #include <windows.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_GETTIMEOFDAY)
  #include <sys/time.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

  #ifndef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 199309
  #endif

  #include <time.h>

  #ifndef CLOCK_REALTIME
    #define CLOCK_REALTIME 0
  #endif

#endif

namespace Botan {

namespace {

/*
* Combine a two time values into a single one
*/
u64bit combine_timers(u32bit seconds, u32bit parts, u32bit parts_hz)
   {
   static const u64bit NANOSECONDS_UNITS = 1000000000;

   u64bit res = seconds * NANOSECONDS_UNITS;
   res += parts * (NANOSECONDS_UNITS / parts_hz);
   return res;
   }

std::tm do_gmtime(time_t time_val)
   {
   std::tm tm;

#if defined(BOTAN_TARGET_OS_HAS_GMTIME_S)
   gmtime_s(&tm, &time_val); // Windows
#elif defined(BOTAN_TARGET_OS_HAS_GMTIME_R)
   gmtime_r(&time_val, &tm); // Unix/SUSv2
#else
   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == 0)
      throw Encoding_Error("time_t_to_tm could not convert");
   tm = *tm_p;
#endif

   return tm;
   }

}

/*
* Get the system clock
*/
u64bit system_time()
   {
   return static_cast<u64bit>(std::time(0));
   }

/*
* Convert a time_point to a calendar_point
*/
calendar_point calendar_value(u64bit a_time_t)
   {
   std::tm tm = do_gmtime(static_cast<std::time_t>(a_time_t));

   return calendar_point(tm.tm_year + 1900,
                         tm.tm_mon + 1,
                         tm.tm_mday,
                         tm.tm_hour,
                         tm.tm_min,
                         tm.tm_sec);
   }

u64bit get_nanoseconds_clock()
   {
#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

   struct ::timespec tv;
   ::clock_gettime(CLOCK_REALTIME, &tv);
   return combine_timers(tv.tv_sec, tv.tv_nsec, 1000000000);

#elif defined(BOTAN_TARGET_OS_HAS_GETTIMEOFDAY)

   struct ::timeval tv;
   ::gettimeofday(&tv, 0);
   return combine_timers(tv.tv_sec, tv.tv_usec, 1000000);

#elif defined(BOTAN_TARGET_OS_HAS_WIN32_GET_SYSTEMTIME)

   // Returns time since January 1, 1601 in 100-ns increments
   ::FILETIME tv;
   ::GetSystemTimeAsFileTime(&tv);
   u64bit tstamp = (static_cast<u64bit>(tv.dwHighDateTime) << 32) |
                   tv.dwLowDateTime;

   return (tstamp * 100); // Scale to 1 nanosecond units

#else

   return combine_timers(static_cast<u32bit>(std::time(0)),
                         std::clock(), CLOCKS_PER_SEC);

#endif
   }

}
