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
      case CPUFeature::Bit::NEON:
         return "neon";
      case CPUFeature::Bit::SVE:
         return "sve";
      case CPUFeature::Bit::SHA1:
         return "armv8sha1";
      case CPUFeature::Bit::SHA2:
         return "armv8sha2";
      case CPUFeature::Bit::AES:
         return "armv8aes";
      case CPUFeature::Bit::PMULL:
         return "armv8pmull";
      case CPUFeature::Bit::SHA3:
         return "armv8sha3";
      case CPUFeature::Bit::SHA2_512:
         return "armv8sha2_512";
      case CPUFeature::Bit::SM3:
         return "armv8sm3";
      case CPUFeature::Bit::SM4:
         return "armv8sm4";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   // TODO(Botan4) remove the "arm_xxx" strings here
   if(tok == "neon" || tok == "simd") {
      return CPUFeature::Bit::NEON;
   } else if(tok == "sve" || tok == "arm_sve") {
      return CPUFeature::Bit::SVE;
   } else if(tok == "armv8sha1" || tok == "arm_sha1") {
      return CPUFeature::Bit::SHA1;
   } else if(tok == "armv8sha2" || tok == "arm_sha2") {
      return CPUFeature::Bit::SHA2;
   } else if(tok == "armv8aes" || tok == "arm_aes") {
      return CPUFeature::Bit::AES;
   } else if(tok == "armv8pmull" || tok == "arm_pmull") {
      return CPUFeature::Bit::PMULL;
   } else if(tok == "armv8sha3" || tok == "arm_sha3") {
      return CPUFeature::Bit::SHA3;
   } else if(tok == "armv8sha2_512" || tok == "arm_sha2_512") {
      return CPUFeature::Bit::SHA2_512;
   } else if(tok == "armv8sm3" || tok == "arm_sm3") {
      return CPUFeature::Bit::SM3;
   } else if(tok == "armv8sm4" || tok == "arm_sm4") {
      return CPUFeature::Bit::SM4;
   } else {
      return {};
   }
}

}  // namespace Botan
