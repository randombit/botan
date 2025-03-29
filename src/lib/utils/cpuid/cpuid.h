/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CPUID_H_
#define BOTAN_CPUID_H_

#include <botan/types.h>
#include <botan/internal/target_info.h>
#include <optional>
#include <string>

#if defined(BOTAN_HAS_CPUID_DETECTION)
   #include <botan/internal/cpuid_features.h>
#endif

namespace Botan {

#if !defined(BOTAN_HAS_CPUID_DETECTION)
// A no-op CPUFeature
class BOTAN_TEST_API CPUFeature {
   public:
      enum Bit : uint32_t {};

      uint32_t as_u32() const;

      CPUFeature(Bit) {}

      static std::optional<CPUFeature> from_string(std::string_view);

      std::string to_string() const;
};
#endif

/**
* A class handling runtime CPU feature detection. It is limited to
* just the features necessary to implement CPU specific code in Botan,
* rather than being a general purpose utility.
*/
class BOTAN_TEST_API CPUID final {
   public:
      typedef CPUFeature Feature;

      /**
      * Probe the CPU and see what extensions are supported
      */
      static void initialize();

      /**
      * Return a possibly empty string containing list of known CPU
      * extensions. Each name will be seperated by a space, and the ordering
      * will be arbitrary. This list only contains values that are useful to
      * Botan (for example FMA instructions are not checked).
      *
      * Example outputs "sse2 ssse3 rdtsc", "neon arm_aes", "altivec"
      */
      static std::string to_string();

      /**
      * Return true if a 4x32 SIMD instruction set is available
      * (SSE2/SSSE3, NEON, Altivec/VMX, or LSX)
      */
      static bool has_simd_4x32() {
#if defined(BOTAN_TARGET_CPU_SUPPORTS_SSSE3)
         return CPUID::has(CPUID::Feature::SSSE3);
#elif defined(BOTAN_TARGET_CPU_SUPPORTS_NEON)
         return CPUID::has(CPUID::Feature::NEON);
#elif defined(BOTAN_TARGET_CPU_SUPPORTS_ALTIVEC)
         return CPUID::has(CPUID::Feature::ALTIVEC);
#elif defined(BOTAN_TARGET_CPU_SUPPORTS_LSX)
         return CPUID::has(CPUID::Feature::LSX);
#else
         return false;
#endif
      }

      /**
      * Check if the processor supports hardware AES instructions
      */
      static bool has_hw_aes() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has(CPUID::Feature::AESNI);
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has(CPUID::Feature::AES);
#elif defined(BOTAN_TARGET_CPU_IS_PPC64)
         return has(CPUID::Feature::POWER_CRYPTO);
#else
         return false;
#endif
      }

      /**
      * Check if the processor supports carryless multiply (CLMUL, PMULL, VMUL)
      */
      static bool has_carryless_multiply() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has(CPUID::Feature::CLMUL);
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has(CPUID::Feature::PMULL);
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
         return has(CPUID::Feature::POWER_CRYPTO);
#else
         return false;
#endif
      }

      static bool has(CPUID::Feature elem) { return state().has_bit(elem.as_u32()); }

      /*
      * Clear a CPUID bit
      * Call CPUID::initialize to reset
      *
      * This is only exposed for testing and should never be called within the library
      */
      static void clear_cpuid_bit(CPUID::Feature bit) { state().clear_cpuid_bit(bit.as_u32()); }

      static std::optional<CPUID::Feature> bit_from_string(std::string_view tok);

      /**
      * A common helper for the various CPUID implementations
      */
      template <typename T>
      static inline uint32_t if_set(uint64_t cpuid, T flag, CPUID::Feature bit, uint32_t allowed) {
         const uint64_t flag64 = static_cast<uint64_t>(flag);
         if((cpuid & flag64) == flag64) {
            return (bit.as_u32() & allowed);
         } else {
            return 0;
         }
      }

   private:
      struct CPUID_Data {
         public:
            CPUID_Data();

            CPUID_Data(const CPUID_Data& other) = default;
            CPUID_Data& operator=(const CPUID_Data& other) = default;

            void clear_cpuid_bit(uint32_t bit) { m_processor_features &= ~bit; }

            bool has_bit(uint32_t bit) const { return (m_processor_features & bit) == bit; }

            uint32_t bitset() const { return m_processor_features; }

         private:
#if defined(BOTAN_HAS_CPUID_DETECTION)
            static uint32_t detect_cpu_features(uint32_t allowed_bits);
#endif

            uint32_t m_processor_features;
      };

      static CPUID_Data& state() {
         static CPUID::CPUID_Data g_cpuid;
         return g_cpuid;
      }
};

}  // namespace Botan

#endif
