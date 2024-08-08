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

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   uint32_t feat = 0;

   #if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   /*
   * On systems with getauxval these bits should normally be defined
   * in bits/auxv.h but some buggy? glibc installs seem to miss them.
   * These following values are all fixed, for the Linux ELF format,
   * so we just hardcode them in ARM_hwcap_bit enum.
   */

   enum class ARM_hwcap_bit : uint64_t {
      NEON_bit = (1 << 12),
      AES_bit = (1 << 0),
      PMULL_bit = (1 << 1),
      SHA1_bit = (1 << 2),
      SHA2_bit = (1 << 3),
   };

   constexpr unsigned long hwcap_neon = 16;    // AT_HWCAP
   constexpr unsigned long hwcap_crypto = 26;  // AT_HWCAP2

   const uint64_t hwcap_neon = OS::get_auxval(hwcap_neon);

   feat |= if_set(hwcap_neon, ARM_hwcap_bit::NEON_bit, CPUID::CPUID_ARM_NEON_BIT, allowed);

   if(feat & CPUID::CPUID_ARM_NEON_BIT) {
      const uint64_t hwcap_crypto = OS::get_auxval(hwcap_crypto);

      feat |= if_set(hwcap_crypto, ARM_hwcap_bit::AES_bit, CPUID::CPUID_ARM_AES_BIT, allowed);

      feat |= if_set(hwcap_crypto, ARM_hwcap_bit::PMULL_bit, CPUID::CPUID_ARM_PMULL_BIT, allowed);

      feat |= if_set(hwcap_crypto, ARM_hwcap_bit::SHA1_bit, CPUID::CPUID_ARM_SHA1_BIT, allowed);

      feat |= if_set(hwcap_crypto, ARM_hwcap_bit::SHA2_bit, CPUID::CPUID_ARM_SHA2_BIT, allowed);
   }
   #endif

   return feat;
}

}  // namespace Botan

#endif
