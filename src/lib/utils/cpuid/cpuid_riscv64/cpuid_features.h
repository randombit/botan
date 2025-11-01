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
         SCALAR_AES = (1U << 0),
         SCALAR_SHA256 = (1U << 1),
         SCALAR_SM3 = (1U << 2),
         SCALAR_SM4 = (1U << 3),

         VECTOR = (1 << 16),
         VECTOR_AES = (1U << 17),
         VECTOR_SHA256 = (1U << 18),
         VECTOR_SM3 = (1U << 19),
         VECTOR_SM4 = (1U << 20),
      };

      CPUFeature(Bit b) : m_bit(b) {}

      uint32_t as_u32() const { return static_cast<uint32_t>(m_bit); }

      std::string to_string() const;

      static std::optional<CPUFeature> from_string(std::string_view s);

   private:
      Bit m_bit;
};

}  // namespace Botan

#endif
