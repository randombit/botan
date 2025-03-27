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
      case CPUFeature::Bit::ALTIVEC:
         return "altivec";
      case CPUFeature::Bit::POWER_CRYPTO:
         return "power_crypto";
      case CPUFeature::Bit::DARN:
         return "darn";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   if(tok == "altivec" || tok == "simd") {
      return CPUFeature::Bit::ALTIVEC;
   } else if(tok == "power_crypto") {
      return CPUFeature::Bit::POWER_CRYPTO;
   } else if(tok == "darn" || tok == "darn_rng") {
      // TODO(Botan4) remove "darn_rng"
      return CPUFeature::Bit::DARN;
   } else {
      return {};
   }
}

}  // namespace Botan
