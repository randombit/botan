/**
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TIME_UTILS_H_
#define BOTAN_TIME_UTILS_H_

#include <botan/exceptn.h>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

#include <chrono>

namespace Botan {

template <typename F>
uint64_t measure_cost(std::chrono::milliseconds trial_msec, F func) {
#if defined(BOTAN_HAS_OS_UTILS)
   const uint64_t trial_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(trial_msec).count();

   uint64_t total_nsec = 0;
   uint64_t trials = 0;

   auto trial_start = OS::get_system_timestamp_ns();

   for(;;) {
      const auto start = OS::get_system_timestamp_ns();
      func();
      const auto end = OS::get_system_timestamp_ns();

      if(end >= start) {
         total_nsec += (end - start);
         trials += 1;

         if((end - trial_start) >= trial_nsec) {
            return (total_nsec / trials);
         }
      }
   }

#else
   BOTAN_UNUSED(trial_msec, func);
   throw Not_Implemented("No system clock available");
#endif
}

}  // namespace Botan

#endif
