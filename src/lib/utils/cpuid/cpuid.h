/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CPUID_H_
#define BOTAN_CPUID_H_

#include <botan/types.h>
#include <iosfwd>
#include <string>
#include <vector>

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
   defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   #define BOTAN_CPUID_HAS_DETECTION

#endif

/**
* A class handling runtime CPU feature detection. It is limited to
* just the features necessary to implement CPU specific code in Botan,
* rather than being a general purpose utility.
*
* This class supports:
*
*  - x86 features using CPUID. x86 is also the only processor with
*    accurate cache line detection currently.
*
*  - PowerPC AltiVec detection on Linux, NetBSD, OpenBSD, and macOS
*
*  - ARM NEON and crypto extensions detection. On Linux and Android
*    systems which support getauxval, that is used to access CPU
*    feature information. Otherwise a relatively portable but
*    thread-unsafe mechanism involving executing probe functions which
*    catching SIGILL signal is used.
*/
class BOTAN_TEST_API CPUID final {
   public:
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

      static bool is_little_endian() {
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
         return true;
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
         return false;
#else
         return !has_cpuid_bit(CPUID_IS_BIG_ENDIAN_BIT);
#endif
      }

      static bool is_big_endian() {
#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
         return true;
#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
         return false;
#else
         return has_cpuid_bit(CPUID_IS_BIG_ENDIAN_BIT);
#endif
      }

      /**
      * Return true if a 4x32 SIMD instruction set is available
      * (SSE2, NEON, or Altivec/VMX)
      */
      static bool has_simd_32() {
#if defined(BOTAN_TARGET_SUPPORTS_SSE2)
         return CPUID::has_sse2();
#elif defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)
         return CPUID::has_altivec();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         return CPUID::has_neon();
#else
         return false;
#endif
      }

      /**
      * Return true if a 2x64 SIMD instruction set is available
      * (SSSE3 or NEON)
      */
      static bool has_simd_2x64() {
#if defined(BOTAN_TARGET_SUPPORTS_SSSE3)
         return CPUID::has_ssse3();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
         return CPUID::has_neon();
#else
         return false;
#endif
      }

      enum CPUID_bits : uint32_t {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         // These values have no relation to cpuid bitfields

         // SIMD instruction sets
         CPUID_SSE2_BIT = (1U << 0),
         CPUID_SSSE3_BIT = (1U << 1),
         CPUID_AVX2_BIT = (1U << 2),
         CPUID_AVX512_BIT = (1U << 3),

         // Misc useful instructions
         CPUID_RDTSC_BIT = (1U << 10),
         CPUID_ADX_BIT = (1U << 11),
         CPUID_BMI_BIT = (1U << 12),
         CPUID_GFNI_BIT = (1U << 13),

         // Crypto-specific ISAs
         CPUID_AESNI_BIT = (1U << 16),
         CPUID_CLMUL_BIT = (1U << 17),
         CPUID_RDRAND_BIT = (1U << 18),
         CPUID_RDSEED_BIT = (1U << 19),
         CPUID_SHA_BIT = (1U << 20),
         CPUID_AVX512_AES_BIT = (1U << 21),
         CPUID_AVX512_CLMUL_BIT = (1U << 22),
         CPUID_AVX2_AES_BIT = (1U << 23),
         CPUID_AVX2_CLMUL_BIT = (1U << 24),
         CPUID_SHA512_BIT = (1U << 25),
         CPUID_SM3_BIT = (1U << 26),
         CPUID_SM4_BIT = (1U << 27),
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         CPUID_ALTIVEC_BIT = (1U << 0),
         CPUID_POWER_CRYPTO_BIT = (1U << 1),
         CPUID_DARN_BIT = (1U << 2),
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         CPUID_ARM_NEON_BIT = (1U << 0),
         CPUID_ARM_SVE_BIT = (1U << 1),
         CPUID_ARM_AES_BIT = (1U << 16),
         CPUID_ARM_PMULL_BIT = (1U << 17),
         CPUID_ARM_SHA1_BIT = (1U << 18),
         CPUID_ARM_SHA2_BIT = (1U << 19),
         CPUID_ARM_SHA3_BIT = (1U << 20),
         CPUID_ARM_SHA2_512_BIT = (1U << 21),
         CPUID_ARM_SM3_BIT = (1U << 22),
         CPUID_ARM_SM4_BIT = (1U << 23),
#endif

         CPUID_IS_BIG_ENDIAN_BIT = (1U << 30),
         CPUID_INITIALIZED_BIT = (1U << 31)
      };

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
      /**
      * Check if the processor supports AltiVec/VMX
      */
      static bool has_altivec() { return has_cpuid_bit(CPUID_ALTIVEC_BIT); }

      /**
      * Check if the processor supports POWER8 crypto extensions
      */
      static bool has_power_crypto() { return has_cpuid_bit(CPUID_POWER_CRYPTO_BIT); }

      /**
      * Check if the processor supports POWER9 DARN RNG
      */
      static bool has_darn_rng() { return has_cpuid_bit(CPUID_DARN_BIT); }

#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
      /**
      * Check if the processor supports NEON SIMD
      */
      static bool has_neon() { return has_cpuid_bit(CPUID_ARM_NEON_BIT); }

      /**
      * Check if the processor supports ARMv8 SVE
      */
      static bool has_arm_sve() { return has_cpuid_bit(CPUID_ARM_SVE_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA1
      */
      static bool has_arm_sha1() { return has_cpuid_bit(CPUID_ARM_SHA1_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA2
      */
      static bool has_arm_sha2() { return has_cpuid_bit(CPUID_ARM_SHA2_BIT); }

      /**
      * Check if the processor supports ARMv8 AES
      */
      static bool has_arm_aes() { return has_cpuid_bit(CPUID_ARM_AES_BIT); }

      /**
      * Check if the processor supports ARMv8 PMULL
      */
      static bool has_arm_pmull() { return has_cpuid_bit(CPUID_ARM_PMULL_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA-512
      */
      static bool has_arm_sha2_512() { return has_cpuid_bit(CPUID_ARM_SHA2_512_BIT); }

      /**
      * Check if the processor supports ARMv8 SHA-3
      */
      static bool has_arm_sha3() { return has_cpuid_bit(CPUID_ARM_SHA3_BIT); }

      /**
      * Check if the processor supports ARMv8 SM3
      */
      static bool has_arm_sm3() { return has_cpuid_bit(CPUID_ARM_SM3_BIT); }

      /**
      * Check if the processor supports ARMv8 SM4
      */
      static bool has_arm_sm4() { return has_cpuid_bit(CPUID_ARM_SM4_BIT); }

#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

      /**
      * Check if the processor supports RDTSC
      */
      static bool has_rdtsc() { return has_cpuid_bit(CPUID_RDTSC_BIT); }

      /**
      * Check if the processor supports SSE2
      */
      static bool has_sse2() { return has_cpuid_bit(CPUID_SSE2_BIT); }

      /**
      * Check if the processor supports SSSE3
      */
      static bool has_ssse3() { return has_cpuid_bit(CPUID_SSSE3_BIT); }

      /**
      * Check if the processor supports AVX2
      */
      static bool has_avx2() { return has_cpuid_bit(CPUID_AVX2_BIT); }

      /**
      * Check if the processor supports our AVX-512 minimum profile
      *
      * Namely AVX-512 F, DQ, BW, VL, IFMA, VBMI, VBMI2, BITALG
      */
      static bool has_avx512() { return has_cpuid_bit(CPUID_AVX512_BIT); }

      /**
      * Check if the processor supports AVX-512 AES (VAES)
      *
      * Only set if the baseline AVX-512 profile is also satisfied
      */
      static bool has_avx512_aes() { return has_cpuid_bit(CPUID_AVX512_AES_BIT); }

      /**
      * Check if the processor supports AVX2 AES (VAES)
      */
      static bool has_avx2_vaes() { return has_cpuid_bit(CPUID_AVX2_AES_BIT); }

      /**
      * Check if the processor supports AVX2 CLMUL
      */
      static bool has_avx2_clmul() { return has_cpuid_bit(CPUID_AVX2_CLMUL_BIT); }

      /**
      * Check if the processor supports AVX-512 VPCLMULQDQ
      */
      static bool has_avx512_clmul() { return has_cpuid_bit(CPUID_AVX512_CLMUL_BIT); }

      /**
      * Check if the processor supports BMI2 (and BMI1)
      */
      static bool has_bmi2() { return has_cpuid_bit(CPUID_BMI_BIT); }

      /**
      * Check if the processor supports GFNI
      *
      * A few Atom processors supported GFNI only for SSE; we gate this bit
      * on the processor also supporting GFNI-AVX2
      */
      static bool has_gfni() { return has_cpuid_bit(CPUID_GFNI_BIT); }

      /**
      * Check if the processor supports AES-NI
      */
      static bool has_aes_ni() { return has_cpuid_bit(CPUID_AESNI_BIT); }

      /**
      * Check if the processor supports CLMUL
      */
      static bool has_clmul() { return has_cpuid_bit(CPUID_CLMUL_BIT); }

      /**
      * Check if the processor supports Intel SHA extension
      */
      static bool has_intel_sha() { return has_cpuid_bit(CPUID_SHA_BIT); }

      /**
      * Check if the processor supports Intel SHA-512 extension
      */
      static bool has_intel_sha512() { return has_cpuid_bit(CPUID_SHA512_BIT); }

      /**
      * Check if the processor supports Intel SM3
      */
      static bool has_intel_sm3() { return has_cpuid_bit(CPUID_SM3_BIT); }

      /**
      * Check if the processor supports Intel SM4
      */
      static bool has_intel_sm4() { return has_cpuid_bit(CPUID_SM4_BIT); }

      /**
      * Check if the processor supports ADX extension
      */
      static bool has_adx() { return has_cpuid_bit(CPUID_ADX_BIT); }

      /**
      * Check if the processor supports RDRAND
      */
      static bool has_rdrand() { return has_cpuid_bit(CPUID_RDRAND_BIT); }

      /**
      * Check if the processor supports RDSEED
      */
      static bool has_rdseed() { return has_cpuid_bit(CPUID_RDSEED_BIT); }
#endif

      /**
      * Check if the processor supports byte-level vector permutes
      * (SSSE3, NEON, Altivec)
      */
      static bool has_vperm() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_ssse3();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_neon();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         return has_altivec();
#else
         return false;
#endif
      }

      /**
      * Check if the processor supports hardware AES instructions
      */
      static bool has_hw_aes() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_aes_ni();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_arm_aes();
#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         return has_power_crypto();
#else
         return false;
#endif
      }

      /**
      * Check if the processor supports carryless multiply
      * (CLMUL, PMULL)
      */
      static bool has_carryless_multiply() {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         return has_clmul();
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         return has_arm_pmull();
#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)
         return has_power_crypto();
#else
         return false;
#endif
      }

      /*
      * Clear a CPUID bit
      * Call CPUID::initialize to reset
      *
      * This is only exposed for testing, don't use unless you know
      * what you are doing.
      */
      static void clear_cpuid_bit(CPUID_bits bit) { state().clear_cpuid_bit(static_cast<uint32_t>(bit)); }

      /*
      * Don't call this function, use CPUID::has_xxx above
      * It is only exposed for the tests.
      */
      static bool has_cpuid_bit(CPUID_bits elem) {
         const uint32_t elem32 = static_cast<uint32_t>(elem);
         return state().has_bit(elem32);
      }

      static std::vector<CPUID::CPUID_bits> bit_from_string(std::string_view tok);

   private:
      /**
      * A common helper for the various CPUID implementations
      */
      template <typename T>
      static inline uint32_t if_set(uint64_t cpuid, T flag, CPUID::CPUID_bits bit, uint32_t allowed) {
         if(cpuid & static_cast<uint64_t>(flag)) {
            return (bit & allowed);
         } else {
            return 0;
         }
      }

      struct CPUID_Data {
         public:
            CPUID_Data();

            CPUID_Data(const CPUID_Data& other) = default;
            CPUID_Data& operator=(const CPUID_Data& other) = default;

            void clear_cpuid_bit(uint32_t bit) { m_processor_features &= ~bit; }

            bool has_bit(uint32_t bit) const { return (m_processor_features & bit) == bit; }

         private:
#if defined(BOTAN_CPUID_HAS_DETECTION)
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
