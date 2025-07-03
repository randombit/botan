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
      enum Bit : uint32_t {
         SSE2 = (1U << 0),
         SSSE3 = (1U << 1),
         AVX2 = (1U << 2),
         AVX512 = (1U << 3),

         RDTSC = (1U << 6),
         ADX = (1U << 7),
         BMI = (1U << 8),
         GFNI = (1U << 9),
         RDRAND = (1U << 10),
         RDSEED = (1U << 11),

         // Crypto-specific ISAs
         AESNI = (1U << 16),
         CLMUL = (1U << 17),
         SHA = (1U << 20),
         SHA512 = (1U << 21),
         AVX2_AES = (1U << 22),
         AVX512_AES = (1U << 23),
         AVX2_CLMUL = (1U << 24),
         AVX512_CLMUL = (1U << 25),
         SM3 = (1U << 26),
         SM4 = (1U << 27),

         SIMD_4X32 = SSSE3,
         HW_AES = AESNI,
         HW_CLMUL = CLMUL,
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
