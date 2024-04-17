/*
* Runtime CPU detection for Aarch64
* (C) 2009,2010,2013,2017,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#if defined(BOTAN_TARGET_ARCH_IS_ARM64)

   #include <botan/internal/os_utils.h>

   #if defined(BOTAN_TARGET_OS_HAS_SYSCTLBYNAME)
      #include <sys/sysctl.h>
      #include <sys/types.h>
   #endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_ARCH_IS_ARM64)

uint32_t CPUID::CPUID_Data::detect_cpu_features() {
   uint32_t detected_features = 0;

   #if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   /*
   * On systems with getauxval these bits should normally be defined
   * in bits/auxv.h but some buggy? glibc installs seem to miss them.
   * These following values are all fixed, for the Linux ELF format,
   * so we just hardcode them in ARM_hwcap_bit enum.
   */

   enum ARM_hwcap_bit {
      NEON_bit = (1 << 1),
      AES_bit = (1 << 3),
      PMULL_bit = (1 << 4),
      SHA1_bit = (1 << 5),
      SHA2_bit = (1 << 6),
      SHA3_bit = (1 << 17),
      SM3_bit = (1 << 18),
      SM4_bit = (1 << 19),
      SHA2_512_bit = (1 << 21),
      SVE_bit = (1 << 22),

      ARCH_hwcap = 16,  // AT_HWCAP
   };

   const unsigned long hwcap = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap);
   if(hwcap & ARM_hwcap_bit::NEON_bit) {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;
      if(hwcap & ARM_hwcap_bit::AES_bit)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(hwcap & ARM_hwcap_bit::PMULL_bit)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(hwcap & ARM_hwcap_bit::SHA1_bit)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(hwcap & ARM_hwcap_bit::SHA2_bit)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
      if(hwcap & ARM_hwcap_bit::SHA3_bit)
         detected_features |= CPUID::CPUID_ARM_SHA3_BIT;
      if(hwcap & ARM_hwcap_bit::SM3_bit)
         detected_features |= CPUID::CPUID_ARM_SM3_BIT;
      if(hwcap & ARM_hwcap_bit::SM4_bit)
         detected_features |= CPUID::CPUID_ARM_SM4_BIT;
      if(hwcap & ARM_hwcap_bit::SHA2_512_bit)
         detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;
      if(hwcap & ARM_hwcap_bit::SVE_bit)
         detected_features |= CPUID::CPUID_ARM_SVE_BIT;
   }

   #elif defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)

   // All 64-bit Apple ARM chips have NEON, AES, and SHA support
   detected_features |= CPUID::CPUID_ARM_NEON_BIT;
   detected_features |= CPUID::CPUID_ARM_AES_BIT;
   detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
   detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
   detected_features |= CPUID::CPUID_ARM_SHA2_BIT;

   auto sysctlbyname_has_feature = [](const char* feature_name) -> bool {
      unsigned int feature;
      size_t size = sizeof(feature);
      ::sysctlbyname(feature_name, &feature, &size, nullptr, 0);
      return (feature == 1);
   };

   if(sysctlbyname_has_feature("hw.optional.armv8_2_sha3"))
      detected_features |= CPUID::CPUID_ARM_SHA3_BIT;
   if(sysctlbyname_has_feature("hw.optional.armv8_2_sha512"))
      detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;

   #elif defined(BOTAN_USE_GCC_INLINE_ASM)

   /*
   No getauxval API available, fall back on probe functions. We only
   bother with Aarch64 here to simplify the code and because going to
   extreme contortions to detect NEON on devices that probably don't
   support it doesn't seem worthwhile.

   NEON registers v0-v7 are caller saved in Aarch64
   */

   auto neon_probe = []() noexcept -> int {
      asm("and v0.16b, v0.16b, v0.16b");
      return 1;
   };
   auto aes_probe = []() noexcept -> int {
      asm(".word 0x4e284800");
      return 1;
   };
   auto pmull_probe = []() noexcept -> int {
      asm(".word 0x0ee0e000");
      return 1;
   };
   auto sha1_probe = []() noexcept -> int {
      asm(".word 0x5e280800");
      return 1;
   };
   auto sha2_probe = []() noexcept -> int {
      asm(".word 0x5e282800");
      return 1;
   };
   auto sha512_probe = []() noexcept -> int {
      asm(".long 0xcec08000");
      return 1;
   };

   // Only bother running the crypto detection if we found NEON

   if(OS::run_cpu_instruction_probe(neon_probe) == 1) {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

      if(OS::run_cpu_instruction_probe(aes_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(OS::run_cpu_instruction_probe(pmull_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(OS::run_cpu_instruction_probe(sha1_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(OS::run_cpu_instruction_probe(sha2_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
      if(OS::run_cpu_instruction_probe(sha512_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;
   }

   #endif

   return detected_features;
}

#endif

}  // namespace Botan
