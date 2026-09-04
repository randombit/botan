/**
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TIME_UTILS_H_
#define BOTAN_TIME_UTILS_H_

#include <botan/exceptn.h>
#include <botan/internal/target_info.h>
#include <algorithm>
#include <chrono>
#include <limits>
#include <optional>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan {

/**
* Estimate the cost, in nanoseconds, of a single invocation of func
*
* Runs func repeatedly for roughly trial_msec (but always at least a few
* times) and returns the fastest invocation observed. Interference from other
* processes or threads can only ever make an invocation slower, so the minimum
* is the best estimate of the cost of the work itself. Each invocation is timed
* using the CPU time of the calling thread where available, otherwise using a
* monotonic clock.
*/
template <typename F>
uint64_t measure_cost(uint64_t trial_msec, F func) {
#if defined(BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK)
   auto steady_ns = []() -> uint64_t {
      const auto now = std::chrono::steady_clock::now().time_since_epoch();
      return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
   };

   auto thread_cpu_ns = []() -> std::optional<uint64_t> {
   #if defined(BOTAN_HAS_OS_UTILS)
      return OS::get_thread_cpu_time_ns();
   #else
      return std::nullopt;
   #endif
   };

   bool use_cpu_time = thread_cpu_ns().has_value();

   auto sample_ns = [&]() -> uint64_t {
      if(use_cpu_time) {
         return thread_cpu_ns().value_or(0);
      }
      return steady_ns();
   };

   constexpr size_t min_samples = 3;
   const uint64_t trial_nsec = trial_msec * 1000000;
   const uint64_t trial_start = steady_ns();

   uint64_t best = std::numeric_limits<uint64_t>::max();
   size_t samples = 0;

   for(;;) {
      const uint64_t start = sample_ns();
      func();
      const uint64_t end = sample_ns();

      if(end > start) {
         best = std::min(best, end - start);
         samples += 1;
      } else if(use_cpu_time) {
         // The thread CPU clock cannot resolve a single invocation
         use_cpu_time = false;
      }

      if(samples >= min_samples && (steady_ns() - trial_start) >= trial_nsec) {
         return best;
      }
   }

#else
   BOTAN_UNUSED(trial_msec, func);
   throw Not_Implemented("No system clock available");
#endif
}

}  // namespace Botan

#endif
