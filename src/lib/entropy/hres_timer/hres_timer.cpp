/*
* High Resolution Timestamp Entropy Source
* (C) 1999-2009,2011,2014,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hres_timer.h>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
  #include <time.h>
#endif

namespace Botan {

/*
* Get the timestamp
*/
void High_Resolution_Timestamp::poll(Entropy_Accumulator& accum)
   {
   accum.add(OS::get_processor_timestamp(), BOTAN_ENTROPY_ESTIMATE_TIMESTAMPS);

   accum.add(OS::get_system_timestamp_ns(), BOTAN_ENTROPY_ESTIMATE_TIMESTAMPS);

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

#define CLOCK_GETTIME_POLL(src)                                     \
   do {                                                             \
     struct timespec ts;                                            \
     ::clock_gettime(src, &ts);                                     \
     accum.add(&ts, sizeof(ts), BOTAN_ENTROPY_ESTIMATE_TIMESTAMPS); \
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

#endif
   }

}
