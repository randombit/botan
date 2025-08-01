/**
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CPUID_FEATURES_H_
#define BOTAN_CPUID_FEATURES_H_

#include <botan/api.h>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace Botan {

class BOTAN_TEST_API CPUFeature {
   public:
      enum Bit : uint32_t /* NOLINT(performance-enum-size) */ {
         ALTIVEC = (1U << 0),
         POWER_CRYPTO = (1U << 1),
         DARN = (1U << 2),

         SIMD_4X32 = ALTIVEC,
         HW_AES = POWER_CRYPTO,
         HW_CLMUL = POWER_CRYPTO,
      };

      CPUFeature(Bit b) : m_bit(b) {}  // NOLINT(*-explicit-conversions)

      uint32_t as_u32() const { return static_cast<uint32_t>(m_bit); }

      std::string to_string() const;

      static std::optional<CPUFeature> from_string(std::string_view s);

   private:
      Bit m_bit;
};

}  // namespace Botan

#endif
