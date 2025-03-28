/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/internal/os_utils.h>

#if defined(BOTAN_TARGET_OS_IS_LINUX)
   #include <asm/hwprobe.h>
   #include <sys/hwprobe.h>

   #define BOTAN_TARGET_HAS_RISCV_HWPROBE
#endif

namespace Botan {

namespace {

template <std::convertible_to<uint64_t>... Bs>
   requires(sizeof...(Bs) > 0)
constexpr uint64_t bitflag(Bs... bs) {
   return ((uint64_t(1) << bs) | ...);
}

}  // namespace

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   uint32_t feat = 0;

#if defined(BOTAN_TARGET_HAS_RISCV_HWPROBE)
   /*
   * For scalar operations we require additionally
   * Zba (bit 3), Zbb (bit 4), Zkt (bit 16)
   *
   * For vector operations we require
   * V (bit 2), Vbb (bit 17), VZkt (bit 26),
   */
   enum class RISCV_HWPROBE_bit : uint64_t {
      Scalar_Aes = bitflag(3, 4, 16, 11, 12),
      Scalar_Sha256 = bitflag(3, 4, 16, 13),
      Scalar_SM4 = bitflag(3, 4, 16, 14),
      Scalar_SM3 = bitflag(3, 4, 16, 15),

      Vector = bitflag(2, 17, 26),
      Vector_Aes = bitflag(2, 17, 26, 21),
      Vector_Sha256 = bitflag(2, 17, 26, 22, 23),
      Vector_SM4 = bitflag(2, 17, 26, 24),
      Vector_SM3 = bitflag(2, 17, 26, 25),
      Vector_GCM = bitflag(2, 17, 26, 20),
   };

   struct riscv_hwprobe p;
   p.key = RISCV_HWPROBE_KEY_IMA_EXT_0;

   if(__riscv_hwprobe(&p, 1, 0, nullptr, 0) == 0) {
      const uint64_t riscv_features = p.value;

      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_Aes, CPUFeature::Bit::SCALAR_AES, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_Sha256, CPUFeature::Bit::SCALAR_SHA256, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SM3, CPUFeature::Bit::SCALAR_SM3, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SM4, CPUFeature::Bit::SCALAR_SM4, allowed);

      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector, CPUFeature::Bit::VECTOR, allowed);

      if(feat & CPUFeature::Bit::VECTOR) {
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_Aes, CPUFeature::Bit::VECTOR_AES, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_Sha256, CPUFeature::Bit::VECTOR_SHA256, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_SM3, CPUFeature::Bit::VECTOR_SM3, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_SM4, CPUFeature::Bit::VECTOR_SM4, allowed);
      }
   }
#endif

   return feat;
}

}  // namespace Botan
