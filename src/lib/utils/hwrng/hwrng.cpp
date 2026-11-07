/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hwrng.h>

#include <botan/internal/target_info.h>
#include <botan/internal/time_utils.h>
#include <atomic>

namespace Botan::HWRNG {

namespace {

enum class Speed : uint8_t { Unknown, Slow, Fast };

std::atomic<Speed>& speed_state() {
   static std::atomic<Speed> g_speed{Speed::Unknown};
   return g_speed;
}

struct Probe_Result {
      Speed speed = Speed::Slow;
      std::optional<uint64_t> output;
};

/*
* Time the hardware RNG, also returning the last output produced while doing so
*/
Probe_Result probe() {
#if defined(BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK)
   /*
   * A hardware RNG is considered fast if a 64-bit read completes within this
   * many nanoseconds. Per uops.info, RDRAND costs about 65-120 cycles on AMD
   * Zen 3 and later, Intel Ivy Bridge, and Emerald Rapids, but between 575 and
   * 13800 cycles on every other x86 core measured. At typical clock rates 100 ns
   * falls in the gap between these two groups.
   */
   constexpr uint64_t FastThresholdNs = 100;

   // Enough reads per timed batch that the cost of reading the clock is minor
   constexpr size_t ProbeReads = 32;

   // The first read may incur a one-time cost so it is not timed
   std::optional<uint64_t> output = read_once();
   if(!output) {
      return {Speed::Slow, std::nullopt};
   }

   bool ever_failed = false;
   const uint64_t batch_ns = measure_cost(0, [&]() {
      for(size_t i = 0; i != ProbeReads; ++i) {
         if(const auto r = read_once()) {
            output = r;
         } else {
            ever_failed = true;
         }
      }
   });

   // A generator that fails even once during a short probe cannot trusted for fast path
   const bool hwrng_is_slow = ever_failed || (batch_ns > ProbeReads * FastThresholdNs);

   const Speed speed = hwrng_is_slow ? Speed::Slow : Speed::Fast;
   return {speed, output};
#else
   // Without a clock there is no way to time the hardware RNG
   return {Speed::Slow, std::nullopt};
#endif
}

}  // namespace

bool available() {
   return CPUID::has(feature());
}

bool fast() {
   if(!available()) {
      return false;
   }

   auto& state = speed_state();
   Speed speed = state.load();
   if(speed == Speed::Unknown) {
      speed = probe().speed;
      state.store(speed);
   }
   return speed == Speed::Fast;
}

std::optional<uint64_t> read_if_fast() {
   if(!available()) {
      return std::nullopt;
   }

   auto& state = speed_state();
   const Speed speed = state.load();

   if(speed == Speed::Unknown) {
      // Concurrent first calls each probe; the last result stored wins, which is harmless
      const auto probed = probe();
      state.store(probed.speed);
      return probed.output;
   } else if(speed == Speed::Fast) {
      return read();
   } else {
      return std::nullopt;
   }
}

std::optional<uint64_t> read() {
   /*
   * Intel DRNG Software Implementation Guide, Section 5.2.1
   *    It is recommended that applications attempt 10 retries in a tight loop
   *    in the unlikely event that the RDRAND instruction does not return a
   *    random number. This number is based on a binomial probability argument:
   *    given the design margins of the DRNG, the odds of ten failures in a row
   *    are astronomically small and would in fact be an indication of a larger
   *    CPU issue.
   *
   * PowerISA 3.0 p.78:
   *    When the error value is obtained, software is expected to repeat the
   *    operation. [...] The recommended number of attempts may be
   *    implementation specific. In the absence of other guidance, ten attempts
   *    should be adequate.
   */
   constexpr size_t HWRNG_RETRIES = 10;

   for(size_t i = 0; i != HWRNG_RETRIES; ++i) {
      if(const auto output = read_once()) {
         return output;
      }
   }

   return std::nullopt;
}

}  // namespace Botan::HWRNG
