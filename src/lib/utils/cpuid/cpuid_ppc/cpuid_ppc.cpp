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
      const auto [hwcap, hwcap2] = *auxval;

      enum class PPC_hwcap_bit : uint64_t /* NOLINT(performance-enum-size) */ {
         VSX_bit = (1 << 7),
      };

      enum class PPC_hwcap2_bit : uint64_t /* NOLINT(performance-enum-size) */ {
         ARCH_2_07_bit = (1U << 31),
         CRYPTO_bit = (1 << 25),
         DARN_bit = (1 << 21),
      };

      // POWER7 has VSX but lacks the ISA 2.07 vector instructions we rely on
      if((hwcap2 & static_cast<uint64_t>(PPC_hwcap2_bit::ARCH_2_07_bit)) != 0) {
         feat |= if_set(hwcap, PPC_hwcap_bit::VSX_bit, CPUFeature::Bit::VSX, allowed);
      }

      if(is_set(feat, CPUFeature::Bit::VSX)) {
         feat |= if_set(hwcap2, PPC_hwcap2_bit::CRYPTO_bit, CPUFeature::Bit::POWER_CRYPTO, allowed);
      }

      // DARN is a scalar instruction (ISA 3.0) and does not depend on VSX
      feat |= if_set(hwcap2, PPC_hwcap2_bit::DARN_bit, CPUFeature::Bit::DARN, allowed);

      return feat;
   }

#if defined(BOTAN_USE_GCC_INLINE_ASM)

   // NOLINTBEGIN(*-no-assembler)

   /*
   * No auxval available, fall back on probing instructions. A probe is only
   * executed if the associated feature is allowed, so that a cleared feature
   * is never executed even during detection.
   */

   if(is_set(allowed, CPUFeature::Bit::VSX)) {
      // vaddudm is new in ISA 2.07 (POWER8)
      auto vsx_probe = []() noexcept -> int {
         asm volatile("vaddudm 0, 0, 0" ::: "v0");
         return 1;
      };

      if(OS::run_cpu_instruction_probe(vsx_probe) == 1) {
         feat |= CPUFeature::Bit::VSX;
      }
   }

   if(is_set(feat, CPUFeature::Bit::VSX) && is_set(allowed, CPUFeature::Bit::POWER_CRYPTO)) {
      auto vcipher_probe = []() noexcept -> int {
         asm volatile("vcipher 0, 0, 0" ::: "v0");
         return 1;
      };

      if(OS::run_cpu_instruction_probe(vcipher_probe) == 1) {
         feat |= CPUFeature::Bit::POWER_CRYPTO;
      }
   }

   // DARN is a scalar instruction (ISA 3.0) and does not depend on VSX
   if(is_set(allowed, CPUFeature::Bit::DARN)) {
      auto darn_probe = []() noexcept -> int {
         /*
         * DARN returns all ones to indicate a (transient) error. PowerISA 3.0
         * recommends retrying ten times before giving up, as is done in
         * Processor_RNG. Here if DARN never produces a value, it is treated as
         * if the instruction was unavailable.
         */
         for(size_t i = 0; i != 10; ++i) {
            uint64_t output = 0;
            asm volatile("darn %0, 1" : "=r"(output));
            if((~output) != 0) {
               return 1;
            }
         }
         return 0;
      };

      if(OS::run_cpu_instruction_probe(darn_probe) == 1) {
         feat |= CPUFeature::Bit::DARN;
      }
   }

   // NOLINTEND(*-no-assembler)

#endif

   return feat;
}

}  // namespace Botan
