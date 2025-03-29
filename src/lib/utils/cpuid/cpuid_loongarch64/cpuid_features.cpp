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
      case CPUFeature::Bit::LSX:
         return "lsx";
      case CPUFeature::Bit::LASX:
         return "lasx";
      case CPUFeature::Bit::CRYPTO:
         return "crypto";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   if(tok == "lsx") {
      return CPUFeature::Bit::LSX;
   } else if(tok == "lasx") {
      return CPUFeature::Bit::LASX;
   } else if(tok == "crypto") {
      return CPUFeature::Bit::CRYPTO;
   } else {
      return {};
   }
}

}  // namespace Botan
