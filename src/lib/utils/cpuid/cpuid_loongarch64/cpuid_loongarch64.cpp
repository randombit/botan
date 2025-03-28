/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/assert.h>
#include <botan/internal/target_info.h>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan {

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   uint32_t feat = 0;

#if defined(BOTAN_HAS_OS_UTILS)

   if(auto auxval = OS::get_auxval_hwcap()) {
      enum class LoongArch64_hwcap_bit : uint64_t {
         LSX_bit = (1 << 4),
         LASX_bit = (1 << 5),
         CRYPTO_bit = (1 << 8),
      };

      const auto hwcap = auxval->first;

      feat |= if_set(hwcap, LoongArch64_hwcap_bit::LSX_bit, CPUFeature::Bit::LSX, allowed);
      feat |= if_set(hwcap, LoongArch64_hwcap_bit::LASX_bit, CPUFeature::Bit::LASX, allowed);
      feat |= if_set(hwcap, LoongArch64_hwcap_bit::CRYPTO_bit, CPUFeature::Bit::CRYPTO, allowed);
   }
#endif

   return feat;
}

}  // namespace Botan
