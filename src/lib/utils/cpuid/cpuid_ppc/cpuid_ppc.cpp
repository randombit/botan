/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017,2021,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/internal/target_info.h>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

/*
* On macOS and OpenBSD ppc, use sysctl to detect AltiVec
*/
#if defined(BOTAN_TARGET_OS_IS_MACOS)
   #include <sys/sysctl.h>
#elif defined(BOTAN_TARGET_OS_IS_OPENBSD)
   #include <machine/cpu.h>
   #include <sys/param.h>
   #include <sys/sysctl.h>
#endif

namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   uint32_t feat = 0;

#if defined(BOTAN_TARGET_OS_IS_MACOS) || defined(BOTAN_TARGET_OS_IS_OPENBSD)
   // On macOS and OpenBSD, use sysctl
   int sels[2] = {
   #if defined(BOTAN_TARGET_OS_IS_OPENBSD)
      CTL_MACHDEP,
      CPU_ALTIVEC
   #else
      CTL_HW,
      HW_VECTORUNIT
   #endif
   };

   int vector_type = 0;
   size_t length = sizeof(vector_type);
   int error = ::sysctl(sels, 2, &vector_type, &length, NULL, 0);

   if(error == 0 && vector_type > 0) {
      feat |= CPUFeature::Bit::ALTIVEC;
   }

   return feat;

#else  // defined(BOTAN_TARGET_OS_IS_MACOS) || defined(BOTAN_TARGET_OS_IS_OPENBSD)

   #if defined(BOTAN_HAS_OS_UTILS)

   if(auto auxval = OS::get_auxval_hwcap()) {
      const auto [hwcap_altivec, hwcap_crypto] = *auxval;

      enum class PPC_hwcap_bit : uint64_t {
         ALTIVEC_bit = (1 << 28),
         CRYPTO_bit = (1 << 25),
         DARN_bit = (1 << 21),
      };

      feat |= if_set(hwcap_altivec, PPC_hwcap_bit::ALTIVEC_bit, CPUFeature::Bit::ALTIVEC, allowed);

      #if defined(BOTAN_TARGET_ARCH_IS_PPC64)
      if(feat & CPUFeature::Bit::ALTIVEC) {
         feat |= if_set(hwcap_crypto, PPC_hwcap_bit::CRYPTO_bit, CPUFeature::Bit::POWER_CRYPTO, allowed);
         feat |= if_set(hwcap_crypto, PPC_hwcap_bit::DARN_bit, CPUFeature::Bit::DARN, allowed);
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

   if(allowed & CPUFeature::Bit::ALTIVEC) {
      if(OS::run_cpu_instruction_probe(vmx_probe) == 1) {
         feat |= CPUFeature::Bit::ALTIVEC;
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

      if(feat & CPUFeature::Bit::ALTIVEC) {
         if(OS::run_cpu_instruction_probe(vcipher_probe) == 1) {
            feat |= CPUFeature::Bit::POWER_CRYPTO & allowed;
         }

         if(OS::run_cpu_instruction_probe(darn_probe) == 1) {
            feat |= CPUFeature::Bit::DARN & allowed;
         }
      }
      #endif
   }

   #endif

   return feat;

#endif  // defined(BOTAN_TARGET_OS_IS_MACOS) || defined(BOTAN_TARGET_OS_IS_OPENBSD)
}

}  // namespace Botan
