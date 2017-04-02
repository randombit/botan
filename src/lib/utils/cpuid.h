/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CPUID_H__
#define BOTAN_CPUID_H__

#include <botan/types.h>
#include <string>
#include <iosfwd>

namespace Botan {

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
*  - PowerPC AltiVec detection on Linux, NetBSD, OpenBSD, and Darwin
*
*  - ARM NEON and crypto extensions detection. On Linux and Android
*    systems which support getauxval, that is used to access CPU
*    feature information. Otherwise a relatively portable but
*    thread-unsafe mechanism involving executing probe functions which
*    catching SIGILL signal is used.
*/
class BOTAN_DLL CPUID
   {
   public:
      /**
      * Probe the CPU and see what extensions are supported
      */
      static void initialize();

      static bool has_simd_32();

      /**
      * Deprecated equivalent to
      * o << "CPUID flags: " << CPUID::to_string() << "\n";
      */
      BOTAN_DEPRECATED("Use CPUID::to_string")
      static void print(std::ostream& o);

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
      * Return a best guess of the cache line size
      */
      static size_t cache_line_size()
         {
         if(g_processor_features == 0)
            {
            initialize();
            }
         return g_cache_line_size;
         }

      static bool is_little_endian()
         {
         if(g_processor_features == 0)
            {
            initialize();
            }
         return g_little_endian;
         }

      static bool is_big_endian()
         {
         /*
         * We do not support PDP endian, so the endian is
         * always either big or little.
         */
         return is_little_endian() == false;
         }

      enum CPUID_bits : uint64_t
         {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
         // These values have no relation to cpuid bitfields

         // SIMD instruction sets
         CPUID_SSE2_BIT    = (1ULL << 0),
         CPUID_SSSE3_BIT   = (1ULL << 1),
         CPUID_SSE41_BIT   = (1ULL << 2),
         CPUID_SSE42_BIT   = (1ULL << 3),
         CPUID_AVX2_BIT    = (1ULL << 4),
         CPUID_AVX512F_BIT = (1ULL << 5),

         // Misc useful instructions
         CPUID_RDTSC_BIT   = (1ULL << 10),
         CPUID_BMI2_BIT    = (1ULL << 11),
         CPUID_ADX_BIT     = (1ULL << 12),

         // Crypto-specific ISAs
         CPUID_AESNI_BIT   = (1ULL << 16),
         CPUID_CLMUL_BIT   = (1ULL << 17),
         CPUID_RDRAND_BIT  = (1ULL << 18),
         CPUID_RDSEED_BIT  = (1ULL << 19),
         CPUID_SHA_BIT     = (1ULL << 20),
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
         CPUID_ALTIVEC_BIT = (1ULL << 0),
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
         CPUID_ARM_NEON_BIT  = (1ULL << 0),
         CPUID_ARM_AES_BIT   = (1ULL << 16),
         CPUID_ARM_PMULL_BIT = (1ULL << 17),
         CPUID_ARM_SHA1_BIT  = (1ULL << 18),
         CPUID_ARM_SHA2_BIT  = (1ULL << 19),
#endif

         CPUID_INITIALIZED_BIT = (1ULL << 63)
         };

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
      /**
      * Check if the processor supports AltiVec/VMX
      */
      static bool has_altivec()
         {
         return has_cpuid_bit(CPUID_ALTIVEC_BIT);
         }
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
      /**
      * Check if the processor supports NEON SIMD
      */
      static bool has_neon()
         {
         return has_cpuid_bit(CPUID_ARM_NEON_BIT);
         }

      /**
      * Check if the processor supports ARMv8 SHA1
      */
      static bool has_arm_sha1()
         {
         return has_cpuid_bit(CPUID_ARM_SHA1_BIT);
         }

      /**
      * Check if the processor supports ARMv8 SHA2
      */
      static bool has_arm_sha2()
         {
         return has_cpuid_bit(CPUID_ARM_SHA2_BIT);
         }

      /**
      * Check if the processor supports ARMv8 AES
      */
      static bool has_arm_aes()
         {
         return has_cpuid_bit(CPUID_ARM_AES_BIT);
         }

      /**
      * Check if the processor supports ARMv8 PMULL
      */
      static bool has_arm_pmull()
         {
         return has_cpuid_bit(CPUID_ARM_PMULL_BIT);
         }
#endif

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

      /**
      * Check if the processor supports RDTSC
      */
      static bool has_rdtsc()
         {
         return has_cpuid_bit(CPUID_RDTSC_BIT);
         }

      /**
      * Check if the processor supports SSE2
      */
      static bool has_sse2()
         {
         return has_cpuid_bit(CPUID_SSE2_BIT);
         }

      /**
      * Check if the processor supports SSSE3
      */
      static bool has_ssse3()
         {
         return has_cpuid_bit(CPUID_SSSE3_BIT);
         }

      /**
      * Check if the processor supports SSE4.1
      */
      static bool has_sse41()
         {
         return has_cpuid_bit(CPUID_SSE41_BIT);
         }

      /**
      * Check if the processor supports SSE4.2
      */
      static bool has_sse42()
         {
         return has_cpuid_bit(CPUID_SSE42_BIT);
         }

      /**
      * Check if the processor supports AVX2
      */
      static bool has_avx2()
         {
         return has_cpuid_bit(CPUID_AVX2_BIT);
         }

      /**
      * Check if the processor supports AVX-512F
      */
      static bool has_avx512f()
         {
         return has_cpuid_bit(CPUID_AVX512F_BIT);
         }

      /**
      * Check if the processor supports BMI2
      */
      static bool has_bmi2()
         {
         return has_cpuid_bit(CPUID_BMI2_BIT);
         }

      /**
      * Check if the processor supports AES-NI
      */
      static bool has_aes_ni()
         {
         return has_cpuid_bit(CPUID_AESNI_BIT);
         }

      /**
      * Check if the processor supports CLMUL
      */
      static bool has_clmul()
         {
         return has_cpuid_bit(CPUID_CLMUL_BIT);
         }

      /**
      * Check if the processor supports Intel SHA extension
      */
      static bool has_intel_sha()
         {
         return has_cpuid_bit(CPUID_SHA_BIT);
         }

      /**
      * Check if the processor supports ADX extension
      */
      static bool has_adx()
         {
         return has_cpuid_bit(CPUID_ADX_BIT);
         }

      /**
      * Check if the processor supports RDRAND
      */
      static bool has_rdrand()
         {
         return has_cpuid_bit(CPUID_RDRAND_BIT);
         }

      /**
      * Check if the processor supports RDSEED
      */
      static bool has_rdseed()
         {
         return has_cpuid_bit(CPUID_RDSEED_BIT);
         }
#endif

      /*
      * Clear a CPUID bit
      * Call CPUID::initialize to reset
      *
      * This is only exposed for testing, don't use unless you know
      * what you are doing.
      */
      static void clear_cpuid_bit(CPUID_bits bit)
         {
         const uint64_t mask = ~(static_cast<uint64_t>(bit));
         g_processor_features &= mask;
         }

      /*
      * Don't call this function, use CPUID::has_xxx above
      * It is only exposed for the tests.
      */
      static bool has_cpuid_bit(CPUID_bits elem)
         {
         if(g_processor_features == 0)
            {
            initialize();
            }
         return ((g_processor_features & static_cast<uint64_t>(elem)) != 0);
         }

   private:
      static bool g_little_endian;
      static size_t g_cache_line_size;
      static uint64_t g_processor_features;
   };

}

#endif
