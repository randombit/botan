/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/internal/os_utils.h>

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features() {
   uint32_t detected_features = 0;

   #if(defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_HAS_ELF_AUX_INFO)) && \
      defined(BOTAN_TARGET_ARCH_IS_PPC64)

   enum PPC_hwcap_bit {
      ALTIVEC_bit = (1 << 28),
      CRYPTO_bit = (1 << 25),
      DARN_bit = (1 << 21),

      ARCH_hwcap_altivec = 16,  // AT_HWCAP
      ARCH_hwcap_crypto = 26,   // AT_HWCAP2
   };

   const unsigned long hwcap_altivec = OS::get_auxval(PPC_hwcap_bit::ARCH_hwcap_altivec);
   if(hwcap_altivec & PPC_hwcap_bit::ALTIVEC_bit) {
      detected_features |= CPUID::CPUID_ALTIVEC_BIT;

      const unsigned long hwcap_crypto = OS::get_auxval(PPC_hwcap_bit::ARCH_hwcap_crypto);
      if(hwcap_crypto & PPC_hwcap_bit::CRYPTO_bit)
         detected_features |= CPUID::CPUID_POWER_CRYPTO_BIT;
      if(hwcap_crypto & PPC_hwcap_bit::DARN_bit)
         detected_features |= CPUID::CPUID_DARN_BIT;
   }

   #else

   auto vmx_probe = []() noexcept -> int {
      asm("vor 0, 0, 0");
      return 1;
   };

   if(OS::run_cpu_instruction_probe(vmx_probe) == 1) {
      detected_features |= CPUID::CPUID_ALTIVEC_BIT;

      #if defined(BOTAN_TARGET_ARCH_IS_PPC64)
      auto vcipher_probe = []() noexcept -> int {
         asm("vcipher 0, 0, 0");
         return 1;
      };

      if(OS::run_cpu_instruction_probe(vcipher_probe) == 1)
         detected_features |= CPUID::CPUID_POWER_CRYPTO_BIT;

      auto darn_probe = []() noexcept -> int {
         uint64_t output = 0;
         asm volatile("darn %0, 1" : "=r"(output));
         return (~output) != 0;
      };

      if(OS::run_cpu_instruction_probe(darn_probe) == 1)
         detected_features |= CPUID::CPUID_DARN_BIT;
      #endif
   }

   #endif

   return detected_features;
}

}  // namespace Botan

#endif
