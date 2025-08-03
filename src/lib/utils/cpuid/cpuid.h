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
      * Check if a feature is supported returning the associated string if so
      *
      * This is a helper function used to implement provider()
      */
      static std::optional<std::string> check(CPUID::Feature feat) {
         if(state().has_bit(feat.as_u32())) {
            return feat.to_string();
         } else {
            return {};
         }
      }

      /**
      * Check if a feature is supported returning the associated string if so
      *
      * This is a helper function used to implement provider()
      */
      static std::optional<std::string> check(CPUID::Feature feat1, CPUID::Feature feat2) {
         if(state().has_bit((feat1.as_u32() | feat2.as_u32()))) {
            // Typically feat2 is a secondary feature that is almost but not
            // completely implied by feat1 (ex: AVX2 + BMI2) which we have to
            // check for completness, but don't reflect into the provider name.
            return feat1.to_string();
         } else {
            return {};
         }
      }

      /**
      * Check if a feature is supported
      */
      static bool has(CPUID::Feature feat) { return state().has_bit(feat.as_u32()); }

      /**
      * Check if two features are both supported
      */
      static bool has(CPUID::Feature feat1, CPUID::Feature feat2) {
         return state().has_bit(feat1.as_u32() | feat2.as_u32());
      }

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
      static inline bool is_set(uint32_t allowed, CPUID::Feature bit) {
         const uint32_t feat_bit = bit.as_u32();
         return ((allowed & feat_bit) == feat_bit);
      }

      struct CPUID_Data {
         public:
            CPUID_Data();

            CPUID_Data(const CPUID_Data& other) = default;
            CPUID_Data(CPUID_Data&& other) = default;
            CPUID_Data& operator=(const CPUID_Data& other) = default;
            CPUID_Data& operator=(CPUID_Data&& other) = default;
            ~CPUID_Data() = default;

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
