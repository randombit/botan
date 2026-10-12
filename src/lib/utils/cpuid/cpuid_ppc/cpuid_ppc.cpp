/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017,2021,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/internal/os_utils.h>
#include <botan/internal/target_info.h>

namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features([[maybe_unused]] uint32_t allowed) {
   uint32_t feat = 0;

   if(auto auxval = OS::get_auxval_hwcap()) {
      const auto [hwcap_altivec, hwcap_crypto] = *auxval;

      enum class PPC_hwcap_bit : uint64_t /* NOLINT(performance-enum-size) */ {
         ALTIVEC_bit = (1 << 28),
         CRYPTO_bit = (1 << 25),
         DARN_bit = (1 << 21),
      };

      feat |= if_set(hwcap_altivec, PPC_hwcap_bit::ALTIVEC_bit, CPUFeature::Bit::ALTIVEC, allowed);

      if(is_set(feat, CPUFeature::Bit::ALTIVEC)) {
         feat |= if_set(hwcap_crypto, PPC_hwcap_bit::CRYPTO_bit, CPUFeature::Bit::POWER_CRYPTO, allowed);
         feat |= if_set(hwcap_crypto, PPC_hwcap_bit::DARN_bit, CPUFeature::Bit::DARN, allowed);
      }

      return feat;
   }

#if defined(BOTAN_USE_GCC_INLINE_ASM)

   // NOLINTBEGIN(*-no-assembler)

   if(is_set(allowed, CPUFeature::Bit::ALTIVEC)) {
      auto vmx_probe = []() noexcept -> int {
         asm("vor 0, 0, 0");
         return 1;
      };

      if(OS::run_cpu_instruction_probe(vmx_probe) == 1) {
         feat |= CPUFeature::Bit::ALTIVEC;
      }

      if(is_set(feat, CPUFeature::Bit::ALTIVEC)) {
         auto vcipher_probe = []() noexcept -> int {
            asm("vcipher 0, 0, 0");
            return 1;
         };

         auto darn_probe = []() noexcept -> int {
            uint64_t output = 0;
            asm volatile("darn %0, 1" : "=r"(output));
            return (~output) != 0;
         };

         if(OS::run_cpu_instruction_probe(vcipher_probe) == 1) {
            feat |= CPUFeature::Bit::POWER_CRYPTO & allowed;
         }

         if(OS::run_cpu_instruction_probe(darn_probe) == 1) {
            feat |= CPUFeature::Bit::DARN & allowed;
         }
      }
   }

   // NOLINTBEGIN(*-no-assembler)

#endif

   return feat;
}

}  // namespace Botan
