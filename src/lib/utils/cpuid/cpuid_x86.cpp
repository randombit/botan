/*
* Runtime CPU detection for x86
* (C) 2009,2010,2013,2017,2023,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/mem_ops.h>
#include <botan/internal/loadstor.h>

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   #include <immintrin.h>
#endif

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   #include <intrin.h>
#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

namespace {

void invoke_cpuid(uint32_t type, uint32_t out[4]) {
   clear_mem(out, 4);

   #if defined(BOTAN_USE_GCC_INLINE_ASM)
   asm volatile("cpuid\n\t" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(type));

   #elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   __cpuid((int*)out, type);

   #else
   BOTAN_UNUSED(type);
      #warning "No way of calling x86 cpuid instruction for this compiler"
   #endif
}

void invoke_cpuid_sublevel(uint32_t type, uint32_t level, uint32_t out[4]) {
   clear_mem(out, 4);

   #if defined(BOTAN_USE_GCC_INLINE_ASM)
   asm volatile("cpuid\n\t" : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3]) : "0"(type), "2"(level));

   #elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)
   __cpuidex((int*)out, type, level);

   #else
   BOTAN_UNUSED(type, level);
      #warning "No way of calling x86 cpuid instruction for this compiler"
   #endif
}

BOTAN_FUNC_ISA("xsave") uint64_t xgetbv() {
   return _xgetbv(0);
}

}  // namespace

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   enum class x86_CPUID_1_bits : uint64_t {
      RDTSC = (1ULL << 4),
      SSE2 = (1ULL << 26),
      CLMUL = (1ULL << 33),
      SSSE3 = (1ULL << 41),
      SSE41 = (1ULL << 51),
      AESNI = (1ULL << 57),
      // AVX + OSXSAVE
      OSXSAVE = (1ULL << 59) | (1ULL << 60),
      RDRAND = (1ULL << 62)
   };

   enum class x86_CPUID_7_bits : uint64_t {
      BMI1 = (1ULL << 3),
      AVX2 = (1ULL << 5),
      BMI2 = (1ULL << 8),
      BMI_1_AND_2 = BMI1 | BMI2,
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
      GFNI = (1ULL << 40),
      AVX512_VAES = (1ULL << 41),
      AVX512_VCLMUL = (1ULL << 42),
      AVX512_VBITALG = (1ULL << 44),

      /*
      We only enable AVX512 support if all of the below flags are available

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
      AVX512_PROFILE =
         AVX512_F | AVX512_DQ | AVX512_IFMA | AVX512_BW | AVX512_VL | AVX512_VBMI | AVX512_VBMI2 | AVX512_VBITALG,
   };

   // NOLINTNEXTLINE(performance-enum-size)
   enum class x86_CPUID_7_1_bits : uint64_t {
      SHA512 = (1 << 0),
      SM3 = (1 << 1),
      SM4 = (1 << 2),
   };

   uint32_t feat = 0;
   uint32_t cpuid[4] = {0};
   bool has_os_ymm_support = false;
   bool has_os_zmm_support = false;

   // CPUID 0: vendor identification, max sublevel
   invoke_cpuid(0, cpuid);

   const uint32_t max_supported_sublevel = cpuid[0];

   if(max_supported_sublevel >= 1) {
      // CPUID 1: feature bits
      invoke_cpuid(1, cpuid);
      const uint64_t flags0 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[3];

      feat |= if_set(flags0, x86_CPUID_1_bits::RDTSC, CPUID::CPUID_RDTSC_BIT, allowed);

      feat |= if_set(flags0, x86_CPUID_1_bits::RDRAND, CPUID::CPUID_RDRAND_BIT, allowed);

      feat |= if_set(flags0, x86_CPUID_1_bits::SSE2, CPUID::CPUID_SSE2_BIT, allowed);

      if(feat & CPUID::CPUID_SSE2_BIT) {
         feat |= if_set(flags0, x86_CPUID_1_bits::SSSE3, CPUID::CPUID_SSSE3_BIT, allowed);

         if(feat & CPUID::CPUID_SSSE3_BIT) {
            feat |= if_set(flags0, x86_CPUID_1_bits::CLMUL, CPUID::CPUID_CLMUL_BIT, allowed);
            feat |= if_set(flags0, x86_CPUID_1_bits::AESNI, CPUID::CPUID_AESNI_BIT, allowed);
         }

         const uint64_t osxsave64 = static_cast<uint64_t>(x86_CPUID_1_bits::OSXSAVE);
         if((flags0 & osxsave64) == osxsave64) {
            const uint64_t xcr_flags = xgetbv();
            if((xcr_flags & 0x6) == 0x6) {
               has_os_ymm_support = true;
               has_os_zmm_support = (xcr_flags & 0xE0) == 0xE0;
            }
         }
      }
   }

   if(max_supported_sublevel >= 7) {
      clear_mem(cpuid, 4);
      invoke_cpuid_sublevel(7, 0, cpuid);

      const uint64_t flags7 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[1];

      clear_mem(cpuid, 4);
      invoke_cpuid_sublevel(7, 1, cpuid);
      const uint32_t flags7_1 = cpuid[0];

      feat |= if_set(flags7, x86_CPUID_7_bits::RDSEED, CPUID::CPUID_RDSEED_BIT, allowed);
      feat |= if_set(flags7, x86_CPUID_7_bits::ADX, CPUID::CPUID_ADX_BIT, allowed);

      /*
      We only set the BMI bit if both BMI1 and BMI2 are supported, since
      typically we want to use both extensions in the same code.
      */
      feat |= if_set(flags7, x86_CPUID_7_bits::BMI_1_AND_2, CPUID::CPUID_BMI_BIT, allowed);

      if(feat & CPUID::CPUID_SSSE3_BIT) {
         feat |= if_set(flags7, x86_CPUID_7_bits::SHA, CPUID::CPUID_SHA_BIT, allowed);
         feat |= if_set(flags7_1, x86_CPUID_7_1_bits::SM3, CPUID::CPUID_SM3_BIT, allowed);
      }

      if(has_os_ymm_support) {
         feat |= if_set(flags7, x86_CPUID_7_bits::AVX2, CPUID::CPUID_AVX2_BIT, allowed);

         if(feat & CPUID::CPUID_AVX2_BIT) {
            feat |= if_set(flags7, x86_CPUID_7_bits::GFNI, CPUID::CPUID_GFNI_BIT, allowed);
            feat |= if_set(flags7, x86_CPUID_7_bits::AVX512_VAES, CPUID::CPUID_AVX2_AES_BIT, allowed);
            feat |= if_set(flags7, x86_CPUID_7_bits::AVX512_VCLMUL, CPUID::CPUID_AVX2_CLMUL_BIT, allowed);
            feat |= if_set(flags7_1, x86_CPUID_7_1_bits::SHA512, CPUID::CPUID_SHA512_BIT, allowed);
            feat |= if_set(flags7_1, x86_CPUID_7_1_bits::SM4, CPUID::CPUID_SM4_BIT, allowed);

            if(has_os_zmm_support) {
               feat |= if_set(flags7, x86_CPUID_7_bits::AVX512_PROFILE, CPUID::CPUID_AVX512_BIT, allowed);

               if(feat & CPUID::CPUID_AVX512_BIT) {
                  feat |= if_set(flags7, x86_CPUID_7_bits::AVX512_VAES, CPUID::CPUID_AVX512_AES_BIT, allowed);
                  feat |= if_set(flags7, x86_CPUID_7_bits::AVX512_VCLMUL, CPUID::CPUID_AVX512_CLMUL_BIT, allowed);
               }
            }
         }
      }
   }

   /*
   * If we don't have access to CPUID, we can still safely assume that
   * any x86-64 processor has SSE2 and RDTSC
   */
   #if defined(BOTAN_TARGET_ARCH_IS_X86_64)
   if(feat == 0) {
      feat |= CPUID::CPUID_SSE2_BIT & allowed;
      feat |= CPUID::CPUID_RDTSC_BIT & allowed;
   }
   #endif

   return feat;
}

#endif

}  // namespace Botan
