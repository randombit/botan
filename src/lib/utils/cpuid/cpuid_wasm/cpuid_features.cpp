/**
* (C) 2025 Jack Lloyd
* (C) 2025 polarnis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid_features.h>

#include <botan/exceptn.h>

namespace Botan {

std::string CPUFeature::to_string() const {
   switch(m_bit) {
      case CPUFeature::Bit::SIMD128:
         return "simd128";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   if(tok == "simd128") {
      return CPUFeature::Bit::SIMD128;
   }

   return {};
}

}  // namespace Botan
