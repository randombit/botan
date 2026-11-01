/*
* (C) 2016,2019,2020,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hwrng.h>

namespace Botan::HWRNG {

bool available() {
   return CPUID::has(feature());
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
