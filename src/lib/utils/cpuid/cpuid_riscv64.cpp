/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/internal/os_utils.h>

#if defined(BOTAN_TARGET_ARCH_IS_RISCV64) && defined(BOTAN_TARGET_OS_IS_LINUX)
   #include <asm/hwprobe.h>
   #include <sys/hwprobe.h>

   #define BOTAN_TARGET_HAS_RISCV_HWPROBE
#endif

namespace Botan {

#if defined(BOTAN_TARGET_ARCH_IS_RISCV64)

namespace {

constexpr uint64_t bitflag(uint64_t b) {
   return (static_cast<uint64_t>(1) << b);
}

template<typename... Bs>
constexpr uint64_t bitflag(uint64_t b, Bs... rest) {
   return bitflag(b) | bitflag(rest...);
}

}

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

      Vector_Aes = bitflag(2, 17, 26, 21),
      Vector_Sha256 = bitflag(2, 17, 26, 22, 23),
      Vector_SM4 = bitflag(2, 17, 26, 24),
      Vector_SM3 = bitflag(2, 17, 26, 25),

#if 0
      ZBA          = (1 << 3), // Address generation
      ZBB          = (1 << 4), // Bit manip
      ZBS          = (1 << 5), // Single bit
      ZBC          = (1 << 7), // Carryless mul
      ZBKB         = (1 << 8), // Crypto bit manip
      ZBKC         = (1 << 9), // Crypto carryless
      ZBKX         = (1 << 10), // Crossbar
      ZKND         = (1 << 11), // AES decryption
      ZKNE         = (1 << 12), // AES encryption
      ZKNH         = (1 << 13), // SHA-2
      ZKSED        = (1 << 14), // SM4
      ZKSH         = (1 << 15), // SM3
      ZKT          = (1 << 16), // Data independent
      ZVBB         = (1 << 17), // Vector bit operations
      ZVBC         = (1 << 18), // Vector carryless mul
      ZVKB         = (1 << 19), // Subset of ZVBB
      ZVKG         = (1 << 20), // Vector GCM
      ZVKNED       = (1 << 21), // Vector AES
      ZVKNHA       = (1 << 22), // Vector SHA-2
      ZVKNHB       = (1 << 23), // Vector SHA-2
      ZVKSED       = (1 << 24), // Vector SM4
      ZVKSH        = (1 << 25), // Vector SM3
      ZVKT         = (1 << 26), // Vector constant time
      ZICOND       = (1ULL << 35), // Integer conditional
#endif
   };

   struct riscv_hwprobe p;
   p.key = RISCV_HWPROBE_KEY_IMA_EXT_0;

   if(__riscv_hwprobe(&p, 1, 0, nullptr, 0) == 0) {
      const uint64_t riscv_features = p.value;

      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_Aes, CPUID::CPUID_RISCV64_SCALAR_AES, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_Sha256, CPUID::CPUID_RISCV64_SCALAR_SHA256, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SM3, CPUID::CPUID_RISCV64_SCALAR_SM3, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SM4, CPUID::CPUID_RISCV64_SCALAR_SM4, allowed);

   }
#endif

   return feat;
}

#endif

}  // namespace Botan
