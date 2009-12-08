/**
* Time Functions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/time.h>
#include <botan/exceptn.h>
#include <ctime>

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

/**
* Combine a two time values into a single one
*/
u64bit combine_timers(u32bit seconds, u32bit parts, u32bit parts_hz)
   {
   static const u64bit NANOSECONDS_UNITS = 1000000000;

   u64bit res = seconds * NANOSECONDS_UNITS;
   res += parts * (NANOSECONDS_UNITS / parts_hz);
   return res;
   }

}

/**
* Get the system clock
*/
u64bit system_time()
   {
   return static_cast<u64bit>(std::time(0));
   }

/*
* Convert a time_t to a struct tm
*/
std::tm time_t_to_tm(u64bit timer)
   {
   std::time_t time_val = static_cast<std::time_t>(timer);

   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == 0)
      throw Encoding_Error("time_t_to_tm could not convert");
   return (*tm_p);
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

#else
   return combine_timers(std::time(0), std::clock(), CLOCKS_PER_SEC);

#endif
   }

}
