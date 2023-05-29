/*
* Runtime CPU detection for 32-bit ARM
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#if defined(BOTAN_TARGET_ARCH_IS_ARM32)

   #include <botan/internal/os_utils.h>

namespace Botan {

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
      NEON_bit = (1 << 12),
      AES_bit = (1 << 0),
      PMULL_bit = (1 << 1),
      SHA1_bit = (1 << 2),
      SHA2_bit = (1 << 3),

      ARCH_hwcap_neon = 16,    // AT_HWCAP
      ARCH_hwcap_crypto = 26,  // AT_HWCAP2
   };

   const unsigned long hwcap_neon = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap_neon);
   if(hwcap_neon & ARM_hwcap_bit::NEON_bit) {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

      const unsigned long hwcap_crypto = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap_crypto);
      if(hwcap_crypto & ARM_hwcap_bit::AES_bit)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(hwcap_crypto & ARM_hwcap_bit::PMULL_bit)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(hwcap_crypto & ARM_hwcap_bit::SHA1_bit)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(hwcap_crypto & ARM_hwcap_bit::SHA2_bit)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
   }
   #endif

   return detected_features;
}

}  // namespace Botan

#endif
