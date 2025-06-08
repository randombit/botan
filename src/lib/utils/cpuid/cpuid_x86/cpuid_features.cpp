/**
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid_features.h>

#include <botan/exceptn.h>

namespace Botan {

std::string CPUFeature::to_string() const {
   switch(m_bit) {
      case Bit::SSE2:
         return "sse2";
      case Bit::SSSE3:
         return "ssse3";
      case Bit::AVX2:
         return "avx2";
      case Bit::AVX512:
         return "avx512";
      case Bit::RDTSC:
         return "rdtsc";
      case Bit::ADX:
         return "adx";
      case Bit::BMI:
         return "bmi2";
      case Bit::GFNI:
         return "gfni";
      case Bit::RDRAND:
         return "rdrand";
      case Bit::RDSEED:
         return "rdseed";
      case Bit::AESNI:
         return "aesni";
      case Bit::CLMUL:
         return "clmul";
      case Bit::SHA:
         return "intel_sha";
      case Bit::SHA512:
         return "intel_sha512";
      case Bit::AVX2_AES:
         return "avx2_aes";
      case Bit::AVX512_AES:
         return "avx512_aes";
      case Bit::AVX2_CLMUL:
         return "avx2_clmul";
      case Bit::AVX512_CLMUL:
         return "avx512_clmul";
      case Bit::SM3:
         return "intel_sm3";
      case Bit::SM4:
         return "intel_sm4";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   if(tok == "sse2" || tok == "simd") {
      return CPUFeature(Bit::SSE2);
   } else if(tok == "ssse3") {
      return CPUFeature(Bit::SSSE3);
   } else if(tok == "aesni" || tok == "aes_ni") {
      // aes_ni is the string printed on the console when running "botan cpuid"
      return CPUFeature(Bit::AESNI);
   } else if(tok == "clmul") {
      return CPUFeature(Bit::CLMUL);
   } else if(tok == "avx2") {
      return CPUFeature(Bit::AVX2);
   } else if(tok == "avx512") {
      return CPUFeature(Bit::AVX512);
   } else if(tok == "sha" || tok == "intel_sha") {
      // TODO(Botan4) remove "sha" match here
      return CPUFeature(Bit::SHA);
   } else if(tok == "intel_sha512") {
      return CPUFeature(Bit::SHA512);
   } else if(tok == "rdtsc") {
      return CPUFeature(Bit::RDTSC);
   } else if(tok == "bmi2") {
      return CPUFeature(Bit::BMI);
   } else if(tok == "adx") {
      return CPUFeature(Bit::ADX);
   } else if(tok == "gfni") {
      return CPUFeature(Bit::GFNI);
   } else if(tok == "rdrand") {
      return CPUFeature(Bit::RDRAND);
   } else if(tok == "rdseed") {
      return CPUFeature(Bit::RDSEED);
   } else if(tok == "avx512_aes") {
      return CPUFeature(Bit::AVX512_AES);
   } else if(tok == "avx512_clmul") {
      return CPUFeature(Bit::AVX512_CLMUL);
   } else if(tok == "avx2_vaes" || tok == "avx2_aes") {
      return CPUFeature(Bit::AVX2_AES);
   } else if(tok == "avx2_clmul") {
      return CPUFeature(Bit::AVX2_CLMUL);
   } else if(tok == "intel_sm3") {
      return CPUFeature(Bit::SM3);
   } else if(tok == "intel_sm4") {
      return CPUFeature(Bit::SM4);
   } else {
      return {};
   }
}

}  // namespace Botan
