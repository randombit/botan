/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>
#include <botan/types.h>
#include <botan/exceptn.h>
#include <botan/internal/parsing.h>
#include <botan/internal/os_utils.h>
#include <ostream>

namespace Botan {

bool CPUID::has_simd_32()
   {
#if defined(BOTAN_TARGET_SUPPORTS_SSE2)
   return CPUID::has_sse2();
#elif defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)
   return CPUID::has_altivec();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
   return CPUID::has_neon();
#else
   return true;
#endif
   }

//static
std::string CPUID::to_string()
   {
   std::vector<std::string> flags;

#define CPUID_PRINT(flag) do { if(has_##flag()) { flags.push_back(#flag); } } while(0)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   CPUID_PRINT(rdtsc);

   CPUID_PRINT(sse2);
   CPUID_PRINT(ssse3);
   CPUID_PRINT(sse41);
   CPUID_PRINT(sse42);
   CPUID_PRINT(avx2);

   CPUID_PRINT(bmi1);
   CPUID_PRINT(bmi2);
   CPUID_PRINT(adx);

   CPUID_PRINT(aes_ni);
   CPUID_PRINT(clmul);
   CPUID_PRINT(rdrand);
   CPUID_PRINT(rdseed);
   CPUID_PRINT(intel_sha);

   CPUID_PRINT(avx512);
   CPUID_PRINT(avx512_aes);
   CPUID_PRINT(avx512_clmul);
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   CPUID_PRINT(altivec);
   CPUID_PRINT(power_crypto);
   CPUID_PRINT(darn_rng);
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
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
#endif

#undef CPUID_PRINT

   return string_join(flags, ' ');
   }

//static
void CPUID::initialize()
   {
   state() = CPUID_Data();
   }

CPUID::CPUID_Data::CPUID_Data()
   {
   m_cache_line_size = 0;
   m_processor_features = 0;

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   m_processor_features = detect_cpu_features(&m_cache_line_size);

#endif

   m_processor_features |= CPUID::CPUID_INITIALIZED_BIT;

   if(m_cache_line_size == 0)
      {
      m_cache_line_size = OS::get_cache_line_size();
      if(m_cache_line_size == 0)
         m_cache_line_size = BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE;
      }

   m_endian_status = runtime_check_endian();
   }

//static
CPUID::Endian_Status CPUID::CPUID_Data::runtime_check_endian()
   {
   // Check runtime endian
   const uint32_t endian32 = 0x01234567;
   const uint8_t* e8 = reinterpret_cast<const uint8_t*>(&endian32);

   CPUID::Endian_Status endian = CPUID::Endian_Status::Unknown;

   if(e8[0] == 0x01 && e8[1] == 0x23 && e8[2] == 0x45 && e8[3] == 0x67)
      {
      endian = CPUID::Endian_Status::Big;
      }
   else if(e8[0] == 0x67 && e8[1] == 0x45 && e8[2] == 0x23 && e8[3] == 0x01)
      {
      endian = CPUID::Endian_Status::Little;
      }
   else
      {
      throw Internal_Error("Unexpected endian at runtime, neither big nor little");
      }

   // If we were compiled with a known endian, verify it matches at runtime
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   BOTAN_ASSERT(endian == CPUID::Endian_Status::Little, "Build and runtime endian match");
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   BOTAN_ASSERT(endian == CPUID::Endian_Status::Big, "Build and runtime endian match");
#endif

   return endian;
   }

std::vector<CPUID::CPUID_bits>
CPUID::bit_from_string(const std::string& tok)
   {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(tok == "sse2" || tok == "simd")
      return {CPUID::CPUID_SSE2_BIT};
   if(tok == "ssse3")
      return {CPUID::CPUID_SSSE3_BIT};
   if(tok == "sse41")
      return {CPUID::CPUID_SSE41_BIT};
   if(tok == "sse42")
      return {CPUID::CPUID_SSE42_BIT};
   // aes_ni is the string printed on the console when running "botan cpuid"
   if(tok == "aesni" || tok == "aes_ni")
      return {CPUID::CPUID_AESNI_BIT};
   if(tok == "clmul")
      return {CPUID::CPUID_CLMUL_BIT};
   if(tok == "avx2")
      return {CPUID::CPUID_AVX2_BIT};
   if(tok == "avx512")
      return {CPUID::CPUID_AVX512_BIT};
   // there were two if statements testing "sha" and "intel_sha" separately; combined
   if(tok == "sha" || tok == "intel_sha")
      return {CPUID::CPUID_SHA_BIT};
   if(tok == "rdtsc")
      return {CPUID::CPUID_RDTSC_BIT};
   if(tok == "bmi1")
      return {CPUID::CPUID_BMI1_BIT};
   if(tok == "bmi2")
      return {CPUID::CPUID_BMI2_BIT};
   if(tok == "adx")
      return {CPUID::CPUID_ADX_BIT};
   if(tok == "rdrand")
      return {CPUID::CPUID_RDRAND_BIT};
   if(tok == "rdseed")
      return {CPUID::CPUID_RDSEED_BIT};
   if(tok == "avx512_aes")
      return {CPUID::CPUID_AVX512_AES_BIT};
   if(tok == "avx512_clmul")
      return {CPUID::CPUID_AVX512_CLMUL_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   if(tok == "altivec" || tok == "simd")
      return {CPUID::CPUID_ALTIVEC_BIT};
   if(tok == "power_crypto")
      return {CPUID::CPUID_POWER_CRYPTO_BIT};
   if(tok == "darn_rng")
      return {CPUID::CPUID_DARN_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   if(tok == "neon" || tok == "simd")
      return {CPUID::CPUID_ARM_NEON_BIT};
   if(tok == "arm_sve")
      return {CPUID::CPUID_ARM_SVE_BIT};
   if(tok == "armv8sha1" || tok == "arm_sha1")
      return {CPUID::CPUID_ARM_SHA1_BIT};
   if(tok == "armv8sha2" || tok == "arm_sha2")
      return {CPUID::CPUID_ARM_SHA2_BIT};
   if(tok == "armv8aes" || tok == "arm_aes")
      return {CPUID::CPUID_ARM_AES_BIT};
   if(tok == "armv8pmull" || tok == "arm_pmull")
      return {CPUID::CPUID_ARM_PMULL_BIT};
   if(tok == "armv8sha3" || tok == "arm_sha3")
      return {CPUID::CPUID_ARM_SHA3_BIT};
   if(tok == "armv8sha2_512" || tok == "arm_sha2_512")
      return {CPUID::CPUID_ARM_SHA2_512_BIT};
   if(tok == "armv8sm3" || tok == "arm_sm3")
      return {CPUID::CPUID_ARM_SM3_BIT};
   if(tok == "armv8sm4" || tok == "arm_sm4")
      return {CPUID::CPUID_ARM_SM4_BIT};

#else
   BOTAN_UNUSED(tok);
#endif

   return {};
   }

}
