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
      case SCALAR_AES:
         return "scalar_aes";
      case SCALAR_SHA256:
         return "scalar_sha256";
      case SCALAR_SM3:
         return "scalar_sm3";
      case SCALAR_SM4:
         return "scalar_sm4";
      case VECTOR:
         return "vector";
      case VECTOR_AES:
         return "vector_aes";
      case VECTOR_SHA256:
         return "vector_sha256";
      case VECTOR_SM3:
         return "vector_sm3";
      case VECTOR_SM4:
         return "vector_sm4";
   }
   throw Invalid_State("CPUFeature invalid bit");
}

//static
std::optional<CPUFeature> CPUFeature::from_string(std::string_view tok) {
   if(tok == "scalar_aes") {
      return SCALAR_AES;
   } else if(tok == "scalar_sha256") {
      return SCALAR_SHA256;
   } else if(tok == "scalar_sm3") {
      return SCALAR_SM3;
   } else if(tok == "scalar_sm4") {
      return SCALAR_SM4;
   } else if(tok == "vector") {
      return VECTOR;
   } else if(tok == "vector_aes") {
      return VECTOR_AES;
   } else if(tok == "vector_sha256") {
      return VECTOR_SHA256;
   } else if(tok == "vector_sm3") {
      return VECTOR_SM3;
   } else if(tok == "vector_sm4") {
      return VECTOR_SM4;
   } else {
      return {};
   }
}

}  // namespace Botan
