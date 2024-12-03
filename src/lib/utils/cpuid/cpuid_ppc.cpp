/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017,2021,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   uint32_t feat = 0;

   #if defined(BOTAN_HAS_OS_UTILS)

   if(auto auxval = OS::get_auxval_hwcap()) {
      const auto [hwcap_altivec, hwcap_crypto] = *auxval;

      enum class PPC_hwcap_bit : uint64_t {
         ALTIVEC_bit = (1 << 28),
         CRYPTO_bit = (1 << 25),
         DARN_bit = (1 << 21),
      };

      feat |= if_set(hwcap_altivec, PPC_hwcap_bit::ALTIVEC_bit, CPUID::CPUID_ALTIVEC_BIT, allowed);

      #if defined(BOTAN_TARGET_ARCH_IS_PPC64)
      if(feat & CPUID::CPUID_ALTIVEC_BIT) {
         feat |= if_set(hwcap_crypto, PPC_hwcap_bit::CRYPTO_bit, CPUID::CPUID_POWER_CRYPTO_BIT, allowed);
         feat |= if_set(hwcap_crypto, PPC_hwcap_bit::DARN_bit, CPUID::CPUID_DARN_BIT, allowed);
      }
      #endif

      return feat;
   }
   #endif

   #if defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_HAS_OS_UTILS)
   auto vmx_probe = []() noexcept -> int {
      asm("vor 0, 0, 0");
      return 1;
   };

   if(allowed & CPUID::CPUID_ALTIVEC_BIT) {
      if(OS::run_cpu_instruction_probe(vmx_probe) == 1) {
         feat |= CPUID::CPUID_ALTIVEC_BIT;
      }

      #if defined(BOTAN_TARGET_CPU_IS_PPC64)
      auto vcipher_probe = []() noexcept -> int {
         asm("vcipher 0, 0, 0");
         return 1;
      };

      auto darn_probe = []() noexcept -> int {
         uint64_t output = 0;
         asm volatile("darn %0, 1" : "=r"(output));
         return (~output) != 0;
      };

      if(feat & CPUID::CPUID_ALTIVEC_BIT) {
         if(OS::run_cpu_instruction_probe(vcipher_probe) == 1) {
            feat |= CPUID::CPUID_POWER_CRYPTO_BIT & allowed;
         }

         if(OS::run_cpu_instruction_probe(darn_probe) == 1) {
            feat |= CPUID::CPUID_DARN_BIT & allowed;
         }
      }
      #endif
   }

   #endif

   return feat;
}

#endif

}  // namespace Botan
