/*
* Runtime CPU detection for Aarch64
* (C) 2009,2010,2013,2017,2020,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/assert.h>
#include <botan/internal/target_info.h>
#include <functional>
#include <optional>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_SYSCTLBYNAME)
   #include <sys/sysctl.h>
   #include <sys/types.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   #define NOMINMAX 1
   #define _WINSOCKAPI_  // stop windows.h including winsock.h
   #include <windows.h>
#endif

namespace Botan {

namespace {

std::optional<uint32_t> aarch64_feat_via_auxval(uint32_t allowed) {
#if defined(BOTAN_HAS_OS_UTILS)

   if(auto auxval = OS::get_auxval_hwcap()) {
      uint32_t feat = 0;

      /*
      * On systems with getauxval these bits should normally be defined
      * in bits/auxv.h but some buggy? glibc installs seem to miss them.
      * These following values are all fixed, for the Linux ELF format,
      * so we just hardcode them in ARM_hwcap_bit enum.
      */
      enum class ARM_hwcap_bit : uint64_t /* NOLINT(*-enum-size) */ {
         NEON_bit = (1 << 1),
         AES_bit = (1 << 3),
         PMULL_bit = (1 << 4),
         SHA1_bit = (1 << 5),
         SHA2_bit = (1 << 6),
         SHA3_bit = (1 << 17),
         SM3_bit = (1 << 18),
         SM4_bit = (1 << 19),
         SHA2_512_bit = (1 << 21),
         SVE_bit = (1 << 22),
      };

      const auto hwcap = auxval->first;

      feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::NEON_bit, CPUFeature::Bit::NEON, allowed);

      if((feat & CPUFeature::Bit::NEON) == CPUFeature::Bit::NEON) {
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::AES_bit, CPUFeature::Bit::AES, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::PMULL_bit, CPUFeature::Bit::PMULL, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA1_bit, CPUFeature::Bit::SHA1, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA2_bit, CPUFeature::Bit::SHA2, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA3_bit, CPUFeature::Bit::SHA3, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SM3_bit, CPUFeature::Bit::SM3, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SM4_bit, CPUFeature::Bit::SM4, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA2_512_bit, CPUFeature::Bit::SHA2_512, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SVE_bit, CPUFeature::Bit::SVE, allowed);
      }

      return feat;
   }
#else
   BOTAN_UNUSED(allowed);
#endif

   return {};
}

std::optional<uint32_t> aarch64_feat_using_mac_api(uint32_t allowed) {
#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   uint32_t feat = 0;

   auto sysctlbyname_has_feature = [](const char* feature_name) -> bool {
      unsigned int feature = 0;
      size_t size = sizeof(feature);
      if(::sysctlbyname(feature_name, &feature, &size, nullptr, 0) == 0) {
         return (feature == 1);
      } else {
         return false;
      }
   };

   // All 64-bit Apple ARM chips have NEON, AES, and SHA support
   feat |= CPUFeature::Bit::NEON & allowed;
   if((feat & CPUFeature::Bit::NEON) == CPUFeature::Bit::NEON) {
      feat |= CPUFeature::Bit::AES & allowed;
      feat |= CPUFeature::Bit::PMULL & allowed;
      feat |= CPUFeature::Bit::SHA1 & allowed;
      feat |= CPUFeature::Bit::SHA2 & allowed;

      if(sysctlbyname_has_feature("hw.optional.armv8_2_sha3")) {
         feat |= CPUFeature::Bit::SHA3 & allowed;
      }
      if(sysctlbyname_has_feature("hw.optional.armv8_2_sha512")) {
         feat |= CPUFeature::Bit::SHA2_512 & allowed;
      }
   }

   return feat;
#else
   BOTAN_UNUSED(allowed);
   return {};
#endif
}

std::optional<uint32_t> aarch64_feat_using_win_api(uint32_t allowed) {
#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   uint32_t feat = 0;

   // The Windows Aarch64 ABI requires NEON
   feat |= CPUFeature::Bit::NEON & allowed;

   if((feat & CPUFeature::Bit::NEON) == CPUFeature::Bit::NEON) {
      if(::IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0) {
         feat |= CPUFeature::Bit::AES & allowed;
         feat |= CPUFeature::Bit::PMULL & allowed;
         feat |= CPUFeature::Bit::SHA1 & allowed;
         feat |= CPUFeature::Bit::SHA2 & allowed;
      }

   #if defined(PF_ARM_SVE_INSTRUCTIONS_AVAILABLE)
      if(::IsProcessorFeaturePresent(PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) != 0) {
         feat |= CPUFeature::Bit::SVE & allowed;
      }
   #endif
   }

   return feat;
#else
   BOTAN_UNUSED(allowed);
   return {};
#endif
}

std::optional<uint32_t> aarch64_feat_using_instr_probe(uint32_t allowed) {
#if defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_HAS_OS_UTILS)

   // NOLINTBEGIN(*-no-assembler)

   /*
   No getauxval API available, fall back on probe functions.

   The probes are written using raw encodings so they assemble even if the
   assembler is not told about the relevant extension. Each probe clobbers
   only a caller saved register (v0 or x0).
   */

   auto neon_probe = []() noexcept -> int {
      asm volatile("and v0.16b, v0.16b, v0.16b" ::: "v0");
      return 1;
   };
   auto aes_probe = []() noexcept -> int {
      asm volatile(".inst 0x4e284800" ::: "v0");  // aese v0.16b, v0.16b
      return 1;
   };
   auto pmull_probe = []() noexcept -> int {
      asm volatile(".inst 0x0ee0e000" ::: "v0");  // pmull v0.1q, v0.1d, v0.1d
      return 1;
   };
   auto sha1_probe = []() noexcept -> int {
      asm volatile(".inst 0x5e280800" ::: "v0");  // sha1h s0, s0
      return 1;
   };
   auto sha2_probe = []() noexcept -> int {
      asm volatile(".inst 0x5e282800" ::: "v0");  // sha256su0 v0.4s, v0.4s
      return 1;
   };
   auto sha3_probe = []() noexcept -> int {
      asm volatile(".inst 0xce000000" ::: "v0");  // eor3 v0.16b, v0.16b, v0.16b, v0.16b
      return 1;
   };
   auto sm3_probe = []() noexcept -> int {
      asm volatile(".inst 0xce60c000" ::: "v0");  // sm3partw1 v0.4s, v0.4s, v0.4s
      return 1;
   };
   auto sm4_probe = []() noexcept -> int {
      asm volatile(".inst 0xcec08400" ::: "v0");  // sm4e v0.4s, v0.4s
      return 1;
   };
   auto sha512_probe = []() noexcept -> int {
      asm volatile(".inst 0xcec08000" ::: "v0");  // sha512su0 v0.2d, v0.2d
      return 1;
   };
   auto sve_probe = []() noexcept -> int {
      asm volatile(".inst 0x04bf5020" ::: "x0");  // rdvl x0, #1
      return 1;
   };

   // NOLINTEND(*-no-assembler)

   // Only run the probe if the feature is allowed; a cleared feature should never be executed
   auto probe = [allowed](CPUFeature::Bit bit, const std::function<int()>& probe_fn) -> uint32_t {
      if((allowed & bit) == bit && OS::run_cpu_instruction_probe(probe_fn) == 1) {
         return bit;
      }
      return 0;
   };

   uint32_t feat = probe(CPUFeature::Bit::NEON, neon_probe);

   if((feat & CPUFeature::Bit::NEON) == CPUFeature::Bit::NEON) {
      feat |= probe(CPUFeature::Bit::AES, aes_probe);
      feat |= probe(CPUFeature::Bit::PMULL, pmull_probe);
      feat |= probe(CPUFeature::Bit::SHA1, sha1_probe);
      feat |= probe(CPUFeature::Bit::SHA2, sha2_probe);
      feat |= probe(CPUFeature::Bit::SHA3, sha3_probe);
      feat |= probe(CPUFeature::Bit::SM3, sm3_probe);
      feat |= probe(CPUFeature::Bit::SM4, sm4_probe);
      feat |= probe(CPUFeature::Bit::SHA2_512, sha512_probe);
      feat |= probe(CPUFeature::Bit::SVE, sve_probe);
   }

   return feat;
#else
   BOTAN_UNUSED(allowed);
   return {};
#endif
}

}  // namespace

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   if(auto feat_aux = aarch64_feat_via_auxval(allowed)) {
      return feat_aux.value();
   } else if(auto feat_mac = aarch64_feat_using_mac_api(allowed)) {
      return feat_mac.value();
   } else if(auto feat_win = aarch64_feat_using_win_api(allowed)) {
      return feat_win.value();
   } else if(auto feat_instr = aarch64_feat_using_instr_probe(allowed)) {
      return feat_instr.value();
   } else {
      return 0;
   }
}

}  // namespace Botan
