/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hwrng.h>

#include <botan/assert.h>
#include <botan/internal/buffer_stuffer.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/target_info.h>
#include <botan/internal/time_utils.h>
#include <algorithm>

namespace Botan::HWRNG {

namespace {

/*
* Return true if the hardware RNG is fast, also writing the last output
* produced while timing it to sink (if not null)
*/
bool probe(std::optional<uint64_t>* sink) {
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
      return false;
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

   if(sink != nullptr) {
      *sink = output;
   }

   // A generator that fails even once during a short probe cannot be trusted for fast path
   const bool hwrng_is_slow = ever_failed || (batch_ns > ProbeReads * FastThresholdNs);
   return !hwrng_is_slow;
#else
   // Without a clock there is no way to time the hardware RNG
   BOTAN_UNUSED(sink);
   return false;
#endif
}

bool probe_is_fast(std::optional<uint64_t>* sink = nullptr) {
   // Static initialization runs the probe exactly once, so only one caller's sink is written
   static const bool fast = probe(sink);
   return fast;
}

}  // namespace

bool is_available() {
   return CPUID::has(feature());
}

bool is_fast() {
   return is_available() && probe_is_fast();
}

std::optional<uint64_t> read_if_fast() {
   if(!is_available()) {
      return std::nullopt;
   }

   std::optional<uint64_t> probed_output;
   const bool hwrng_is_fast = probe_is_fast(&probed_output);

   if(probed_output) {
      // This call performed the probe; the entropy was already paid for, so
      // it is used even if the hardware RNG turned out to be slow
      return probed_output;
   } else if(hwrng_is_fast) {
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

bool fill(std::span<uint8_t> out) {
   BufferStuffer stuffer(out);

   while(!stuffer.full()) {
      const auto output = read();
      if(!output) {
         return false;
      }
      const auto bytes = store_le(*output);
      stuffer.append(std::span{bytes}.first(std::min(bytes.size(), stuffer.remaining_capacity())));
   }

   return true;
}

}  // namespace Botan::HWRNG
