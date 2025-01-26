/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/types.h>
#include <botan/internal/parsing.h>
#include <ostream>

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

namespace Botan {

//static
std::string CPUID::to_string() {
   std::vector<std::string> flags;

   auto append_fn = [&](bool flag, const char* flag_name) {
      if(flag) {
         flags.push_back(flag_name);
      }
   };

   // NOLINTNEXTLINE(*-macro-usage)
#define CPUID_PRINT(flag) append_fn(has_##flag(), #flag)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   CPUID_PRINT(rdtsc);

   CPUID_PRINT(sse2);
   CPUID_PRINT(ssse3);
   CPUID_PRINT(avx2);

   CPUID_PRINT(bmi2);
   CPUID_PRINT(adx);
   CPUID_PRINT(gfni);

   CPUID_PRINT(aes_ni);
   CPUID_PRINT(clmul);
   CPUID_PRINT(rdrand);
   CPUID_PRINT(rdseed);
   CPUID_PRINT(intel_sha);
   CPUID_PRINT(intel_sha512);

   CPUID_PRINT(avx2_vaes);
   CPUID_PRINT(avx2_clmul);

   CPUID_PRINT(avx512);
   CPUID_PRINT(avx512_aes);
   CPUID_PRINT(avx512_clmul);

   CPUID_PRINT(intel_sm3);
   CPUID_PRINT(intel_sm4);

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   CPUID_PRINT(altivec);
   CPUID_PRINT(power_crypto);
   CPUID_PRINT(darn_rng);
#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   CPUID_PRINT(neon);
   CPUID_PRINT(arm_sve);

   CPUID_PRINT(arm_sha1);
   CPUID_PRINT(arm_sha2);
   CPUID_PRINT(arm_aes);
   CPUID_PRINT(arm_pmull);
   CPUID_PRINT(arm_sha2_512);
   CPUID_PRINT(arm_sha3);
   CPUID_PRINT(arm_sm3);
   CPUID_PRINT(arm_sm4);
#else
   BOTAN_UNUSED(append_fn);
#endif

#undef CPUID_PRINT

   return string_join(flags, ' ');
}

//static
void CPUID::initialize() {
   state() = CPUID_Data();
}

namespace {

// Returns true if big-endian
bool runtime_check_if_big_endian() {
   // Check runtime endian
   const uint32_t endian32 = 0x01234567;
   const uint8_t* e8 = reinterpret_cast<const uint8_t*>(&endian32);

   bool is_big_endian = false;

   if(e8[0] == 0x01 && e8[1] == 0x23 && e8[2] == 0x45 && e8[3] == 0x67) {
      is_big_endian = true;
   } else if(e8[0] == 0x67 && e8[1] == 0x45 && e8[2] == 0x23 && e8[3] == 0x01) {
      is_big_endian = false;
   } else {
      throw Internal_Error("Unexpected endian at runtime, neither big nor little");
   }

   // If we were compiled with a known endian, verify it matches at runtime
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   BOTAN_ASSERT(!is_big_endian, "Build and runtime endian match");
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   BOTAN_ASSERT(is_big_endian, "Build and runtime endian match");
#endif

   return is_big_endian;
}

#if defined(BOTAN_CPUID_HAS_DETECTION)
uint32_t cleared_cpuid_bits() {
   uint32_t cleared = 0;

   #if defined(BOTAN_HAS_OS_UTILS)
   std::string clear_cpuid_env;
   if(OS::read_env_variable(clear_cpuid_env, "BOTAN_CLEAR_CPUID")) {
      for(const auto& cpuid : split_on(clear_cpuid_env, ',')) {
         for(auto& bit : CPUID::bit_from_string(cpuid)) {
            cleared |= bit;
         }
      }
   }
   #endif

   return cleared;
}
#endif

}  // namespace

CPUID::CPUID_Data::CPUID_Data() {
   m_processor_features = 0;

#if defined(BOTAN_CPUID_HAS_DETECTION)
   m_processor_features = detect_cpu_features(~cleared_cpuid_bits());
#endif

   m_processor_features |= CPUID::CPUID_INITIALIZED_BIT;

   if(runtime_check_if_big_endian()) {
      m_processor_features |= CPUID::CPUID_IS_BIG_ENDIAN_BIT;
   }
}

std::vector<CPUID::CPUID_bits> CPUID::bit_from_string(std::string_view tok) {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(tok == "sse2" || tok == "simd") {
      return {CPUID::CPUID_SSE2_BIT};
   } else if(tok == "ssse3") {
      return {CPUID::CPUID_SSSE3_BIT};
   } else if(tok == "aesni" || tok == "aes_ni") {
      // aes_ni is the string printed on the console when running "botan cpuid"
      return {CPUID::CPUID_AESNI_BIT};
   } else if(tok == "clmul") {
      return {CPUID::CPUID_CLMUL_BIT};
   } else if(tok == "avx2") {
      return {CPUID::CPUID_AVX2_BIT};
   } else if(tok == "avx512") {
      return {CPUID::CPUID_AVX512_BIT};
   }
   // there were two if statements testing "sha" and "intel_sha" separately; combined
   else if(tok == "sha" || tok == "intel_sha") {
      return {CPUID::CPUID_SHA_BIT};
   } else if(tok == "rdtsc") {
      return {CPUID::CPUID_RDTSC_BIT};
   } else if(tok == "bmi2") {
      return {CPUID::CPUID_BMI_BIT};
   } else if(tok == "adx") {
      return {CPUID::CPUID_ADX_BIT};
   } else if(tok == "gfni") {
      return {CPUID::CPUID_GFNI_BIT};
   } else if(tok == "rdrand") {
      return {CPUID::CPUID_RDRAND_BIT};
   } else if(tok == "rdseed") {
      return {CPUID::CPUID_RDSEED_BIT};
   } else if(tok == "avx512_aes") {
      return {CPUID::CPUID_AVX512_AES_BIT};
   } else if(tok == "avx512_clmul") {
      return {CPUID::CPUID_AVX512_CLMUL_BIT};
   } else if(tok == "avx2_vaes") {
      return {CPUID::CPUID_AVX2_AES_BIT};
   } else if(tok == "avx2_clmul") {
      return {CPUID::CPUID_AVX2_CLMUL_BIT};
   } else if(tok == "intel_sm3") {
      return {CPUID::CPUID_SM3_BIT};
   } else if(tok == "intel_sm4") {
      return {CPUID::CPUID_SM4_BIT};
   }

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   if(tok == "altivec" || tok == "simd") {
      return {CPUID::CPUID_ALTIVEC_BIT};
   } else if(tok == "power_crypto") {
      return {CPUID::CPUID_POWER_CRYPTO_BIT};
   } else if(tok == "darn_rng") {
      return {CPUID::CPUID_DARN_BIT};
   }

#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   if(tok == "neon" || tok == "simd") {
      return {CPUID::CPUID_ARM_NEON_BIT};
   } else if(tok == "arm_sve") {
      return {CPUID::CPUID_ARM_SVE_BIT};
   } else if(tok == "armv8sha1" || tok == "arm_sha1") {
      return {CPUID::CPUID_ARM_SHA1_BIT};
   } else if(tok == "armv8sha2" || tok == "arm_sha2") {
      return {CPUID::CPUID_ARM_SHA2_BIT};
   } else if(tok == "armv8aes" || tok == "arm_aes") {
      return {CPUID::CPUID_ARM_AES_BIT};
   } else if(tok == "armv8pmull" || tok == "arm_pmull") {
      return {CPUID::CPUID_ARM_PMULL_BIT};
   } else if(tok == "armv8sha3" || tok == "arm_sha3") {
      return {CPUID::CPUID_ARM_SHA3_BIT};
   } else if(tok == "armv8sha2_512" || tok == "arm_sha2_512") {
      return {CPUID::CPUID_ARM_SHA2_512_BIT};
   } else if(tok == "armv8sm3" || tok == "arm_sm3") {
      return {CPUID::CPUID_ARM_SM3_BIT};
   } else if(tok == "armv8sm4" || tok == "arm_sm4") {
      return {CPUID::CPUID_ARM_SM4_BIT};
   }

#else
   BOTAN_UNUSED(tok);
#endif

   return {};
}

}  // namespace Botan
