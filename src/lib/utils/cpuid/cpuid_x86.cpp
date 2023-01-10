/*
* Runtime CPU detection for x86
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>
#include <botan/mem_ops.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

#include <immintrin.h>

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #include <intrin.h>
#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)
  #include <ia32intrin.h>
#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
  #include <cpuid.h>
#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

namespace {

void invoke_cpuid(uint32_t type, uint32_t out[4])
   {
#if defined(BOTAN_BUILD_COMPILER_IS_MSVC) || defined(BOTAN_BUILD_COMPILER_IS_INTEL)
   __cpuid((int*)out, type);

#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
   __get_cpuid(type, out, out+1, out+2, out+3);

#elif defined(BOTAN_USE_GCC_INLINE_ASM)
   asm("cpuid\n\t"
       : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3])
       : "0" (type));

#else
   #warning "No way of calling x86 cpuid instruction for this compiler"
   clear_mem(out, 4);
#endif
   }

BOTAN_FUNC_ISA("xsave")
uint64_t xgetbv()
   {
   return _xgetbv(0);
   }

void invoke_cpuid_sublevel(uint32_t type, uint32_t level, uint32_t out[4])
   {
#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   __cpuidex((int*)out, type, level);

#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
   __cpuid_count(type, level, out[0], out[1], out[2], out[3]);

#elif defined(BOTAN_USE_GCC_INLINE_ASM)
   asm("cpuid\n\t"
       : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3])     \
       : "0" (type), "2" (level));

#else
   #warning "No way of calling x86 cpuid instruction for this compiler"
   clear_mem(out, 4);
#endif
   }

}

uint64_t CPUID::CPUID_Data::detect_cpu_features(size_t* cache_line_size)
   {
   uint64_t features_detected = 0;
   uint32_t cpuid[4] = { 0 };
   bool has_os_ymm_support = false;
   bool has_os_zmm_support = false;

   // CPUID 0: vendor identification, max sublevel
   invoke_cpuid(0, cpuid);

   const uint32_t max_supported_sublevel = cpuid[0];

   const uint32_t INTEL_CPUID[3] = { 0x756E6547, 0x6C65746E, 0x49656E69 };
   const uint32_t AMD_CPUID[3] = { 0x68747541, 0x444D4163, 0x69746E65 };
   const bool is_intel = same_mem(cpuid + 1, INTEL_CPUID, 3);
   const bool is_amd = same_mem(cpuid + 1, AMD_CPUID, 3);

   if(max_supported_sublevel >= 1)
      {
      // CPUID 1: feature bits
      invoke_cpuid(1, cpuid);
      const uint64_t flags0 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[3];

      enum x86_CPUID_1_bits : uint64_t {
         RDTSC = (1ULL << 4),
         SSE2 = (1ULL << 26),
         CLMUL = (1ULL << 33),
         SSSE3 = (1ULL << 41),
         SSE41 = (1ULL << 51),
         SSE42 = (1ULL << 52),
         AESNI = (1ULL << 57),
         OSXSAVE = (1ULL << 59),
         AVX = (1ULL << 60),
         RDRAND = (1ULL << 62)
      };

      if(flags0 & x86_CPUID_1_bits::RDTSC)
         features_detected |= CPUID::CPUID_RDTSC_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE2)
         features_detected |= CPUID::CPUID_SSE2_BIT;
      if(flags0 & x86_CPUID_1_bits::CLMUL)
         features_detected |= CPUID::CPUID_CLMUL_BIT;
      if(flags0 & x86_CPUID_1_bits::SSSE3)
         features_detected |= CPUID::CPUID_SSSE3_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE41)
         features_detected |= CPUID::CPUID_SSE41_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE42)
         features_detected |= CPUID::CPUID_SSE42_BIT;
      if(flags0 & x86_CPUID_1_bits::AESNI)
         features_detected |= CPUID::CPUID_AESNI_BIT;
      if(flags0 & x86_CPUID_1_bits::RDRAND)
         features_detected |= CPUID::CPUID_RDRAND_BIT;

      if((flags0 & x86_CPUID_1_bits::AVX) &&
         (flags0 & x86_CPUID_1_bits::OSXSAVE))
         {
         const uint64_t xcr_flags = xgetbv();
         if((xcr_flags & 0x6) == 0x6)
            {
            has_os_ymm_support = true;
            has_os_zmm_support = (xcr_flags & 0xE0) == 0xE0;
            }
         }
      }

   if(is_intel)
      {
      // Intel cache line size is in cpuid(1) output
      *cache_line_size = 8 * get_byte<2>(cpuid[1]);
      }
   else if(is_amd)
      {
      // AMD puts it in vendor zone
      invoke_cpuid(0x80000005, cpuid);
      *cache_line_size = get_byte<3>(cpuid[2]);
      }

   if(max_supported_sublevel >= 7)
      {
      clear_mem(cpuid, 4);
      invoke_cpuid_sublevel(7, 0, cpuid);

      enum x86_CPUID_7_bits : uint64_t {
         BMI1 = (1ULL << 3),
         AVX2 = (1ULL << 5),
         BMI2 = (1ULL << 8),
         AVX512_F = (1ULL << 16),
         AVX512_DQ = (1ULL << 17),
         RDSEED = (1ULL << 18),
         ADX = (1ULL << 19),
         AVX512_IFMA = (1ULL << 21),
         SHA = (1ULL << 29),
         AVX512_BW = (1ULL << 30),
         AVX512_VL = (1ULL << 31),
         AVX512_VBMI = (1ULL << 33),
         AVX512_VBMI2 = (1ULL << 38),
         AVX512_VAES = (1ULL << 41),
         AVX512_VCLMUL = (1ULL << 42),
         AVX512_VBITALG = (1ULL << 44),
      };

      const uint64_t flags7 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[1];

      if((flags7 & x86_CPUID_7_bits::AVX2) && has_os_ymm_support)
         features_detected |= CPUID::CPUID_AVX2_BIT;
      if(flags7 & x86_CPUID_7_bits::RDSEED)
         features_detected |= CPUID::CPUID_RDSEED_BIT;
      if(flags7 & x86_CPUID_7_bits::ADX)
         features_detected |= CPUID::CPUID_ADX_BIT;
      if(flags7 & x86_CPUID_7_bits::SHA)
         features_detected |= CPUID::CPUID_SHA_BIT;

      if(flags7 & x86_CPUID_7_bits::BMI1)
         {
         features_detected |= CPUID::CPUID_BMI1_BIT;
         /*
         We only set the BMI2 bit if BMI1 is also supported, so BMI2
         code can safely use both extensions. No known processor
         implements BMI2 but not BMI1.
         */
         if(flags7 & x86_CPUID_7_bits::BMI2)
            {
            features_detected |= CPUID::CPUID_BMI2_BIT;

            /*
            Up until Zen3, AMD CPUs with BMI2 support had microcoded
            pdep/pext, which works but is very slow.

            TODO: check for Zen3 here
            */
            if(is_intel)
               {
               features_detected |= CPUID::CPUID_FAST_PDEP_BIT;
               }
            }
         }

      if((flags7 & x86_CPUID_7_bits::AVX512_F) && has_os_zmm_support)
         {
         const uint64_t AVX512_PROFILE_FLAGS =
            x86_CPUID_7_bits::AVX512_F |
            x86_CPUID_7_bits::AVX512_DQ |
            x86_CPUID_7_bits::AVX512_IFMA |
            x86_CPUID_7_bits::AVX512_BW |
            x86_CPUID_7_bits::AVX512_VL |
            x86_CPUID_7_bits::AVX512_VBMI |
            x86_CPUID_7_bits::AVX512_VBMI2 |
            x86_CPUID_7_bits::AVX512_VBITALG;

         /*
         We only enable AVX512 support if all of the above flags are available

         This is more than we strictly need for most uses, however it also has
         the effect of preventing execution of AVX512 codepaths on cores that
         have serious downclocking problems when AVX512 code executes,
         especially Intel Skylake.

         VBMI2/VBITALG are the key flags here as they restrict us to Intel Ice
         Lake/Rocket Lake, or AMD Zen4, all of which do not have penalties for
         executing AVX512.

         There is nothing stopping some future processor from supporting the
         above flags and having AVX512 penalties, but maybe you should not have
         bought such a processor.
         */
         if((flags7 & AVX512_PROFILE_FLAGS) == AVX512_PROFILE_FLAGS)
            features_detected |= CPUID::CPUID_AVX512_BIT;

         if(flags7 & x86_CPUID_7_bits::AVX512_VAES)
            features_detected |= CPUID::CPUID_AVX512_AES_BIT;
         if(flags7 & x86_CPUID_7_bits::AVX512_VCLMUL)
            features_detected |= CPUID::CPUID_AVX512_CLMUL_BIT;
         }
      }

   /*
   * If we don't have access to CPUID, we can still safely assume that
   * any x86-64 processor has SSE2 and RDTSC
   */
#if defined(BOTAN_TARGET_ARCH_IS_X86_64)
   if(features_detected == 0)
      {
      features_detected |= CPUID::CPUID_SSE2_BIT;
      features_detected |= CPUID::CPUID_RDTSC_BIT;
      }
#endif

   return features_detected;
   }

#endif

}
