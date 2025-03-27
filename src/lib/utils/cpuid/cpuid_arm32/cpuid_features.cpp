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
      case CPUFeature::Bit::SHA1:
         return "armv8sha1";
      case CPUFeature::Bit::SHA2:
         return "armv8sha2";
      case CPUFeature::Bit::AES:
         return "armv8aes";
      case CPUFeature::Bit::PMULL:
         return "armv8pmull";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   // TODO(Botan4) remove the "armv8" strings here
   if(tok == "neon" || tok == "simd") {
      return CPUFeature::Bit::NEON;
   } else if(tok == "armv8sha1" || tok == "arm_sha1") {
      return CPUFeature::Bit::SHA1;
   } else if(tok == "armv8sha2" || tok == "arm_sha2") {
      return CPUFeature::Bit::SHA2;
   } else if(tok == "armv8aes" || tok == "arm_aes") {
      return CPUFeature::Bit::AES;
   } else if(tok == "armv8pmull" || tok == "arm_pmull") {
      return CPUFeature::Bit::PMULL;
   } else {
      return {};
   }
}

}  // namespace Botan
