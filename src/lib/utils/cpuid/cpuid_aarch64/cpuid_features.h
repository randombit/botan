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
      enum Bit : uint32_t /* NOLINT(*-use-enum-class) */ {
         NEON = (1U << 0),
         SVE = (1U << 1),
         AES = (1U << 16),
         PMULL = (1U << 17),
         SHA1 = (1U << 18),
         SHA2 = (1U << 19),
         SHA3 = (1U << 20),
         SHA2_512 = (1U << 21),
         SM3 = (1U << 22),
         SM4 = (1U << 23),

         SIMD_4X32 = NEON,
         HW_AES = AES,
         HW_CLMUL = PMULL,
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
