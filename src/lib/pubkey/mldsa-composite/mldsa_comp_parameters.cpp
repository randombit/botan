
#include "botan/exceptn.h"
#include <botan/asn1_obj.h>
#include <botan/mldsa_comp_parameters.h>
#include <botan/oids.h>
#include <botan/pss_params.h>
#include <string_view>

#include <iostream>

namespace Botan {

static const std::array<MLDSA_Composite_Param, 2> mldsa_composite_registry = {{
   {MLDSA_Composite_Param::id_t::id_MLDSA44_RSA2048_PSS_SHA256,
    "id-MLDSA44-RSA2048-PSS-SHA256",
    "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
    "SHA256",
    "ML-DSA-4x4",
    "2.16.840.1.101.3.4.3.17",  // ML-DSA OID
    "RSA/PSS(SHA-256,MGF1,32)",
    1312,
    2048},
   {MLDSA_Composite_Param::id_t::id_MLDSA44_RSA2048_PKCS15_SHA256,
    "id-MLDSA44-RSA2048-PKCS15-SHA256",
    "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
    "SHA256",
    "ML-DSA-4x4",
    "2.16.840.1.101.3.4.3.17",  // ML-DSA OID
    "RSA",                      // TODO: COMPLETE SIGNATURE ALGORITHM: sha256WithRSAEncryption
    1312,
    2048},
}};

// static
MLDSA_Composite_Param MLDSA_Composite_Param::get_param_by_id_str(std::string_view id_str) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.id_str == id_str) {
         return param;
      }
   }
   throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite id " + std::string(id_str));
}

// static
MLDSA_Composite_Param MLDSA_Composite_Param::get_param_by_id(MLDSA_Composite_Param::id_t id) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.id == id) {
         return param;
      }
   }
   throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite id (enum)");
}

size_t MLDSA_Composite_Param::mldsa_signature_size() const {
   // TODO: USE ENUM, NOT STRING
   if(this->mldsa_variant == std::string("ML-DSA-4x4")) {
      return 2420;
   } else if(this->mldsa_variant == std::string("ML-DSA-6x5")) {
      return 3309;
   } else if(this->mldsa_variant == std::string("ML-DSA-8x7")) {
      return 4627;
   }
   throw Botan::Internal_Error("MLDSA_Composite_Param::mldsa_signature_size() encountered unknown ML-DSA variant ");
}

AlgorithmIdentifier MLDSA_Composite_Param::get_mldsa_algorithm_id() const {
   OID oid(this->mldsa_oid_str);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

// size_t MLDSA_Composite_Param::traditional_pubkey_encoded_size() const {
//    if(std::string(traditional_algoritm).starts_with("RSA")) {
//       std::cout << "MLDSA_Composite_Param::traditional_pubkey_encoded_size() RSA key byte size = "
//                 << (traditional_key_size + 7) / 8 << std::endl;
//       return (traditional_key_size + 7) / 8;
//    }
//    throw Botan::Exception("MLDSA_Composite_Param::traditional_pubkey_encoded_size(): algorithm not implemented");
// }

AlgorithmIdentifier MLDSA_Composite_Param::get_traditional_algorithm_id() const {
   std::optional<OID> oid;
   if(std::string(this->traditional_algoritm).starts_with("RSA")) {
      oid = OID::from_name("RSA");
   } else {
      throw Botan::Exception("not implemented");
   }
   if(!oid.has_value()) {
      throw Botan::Internal_Error(
         "MLDSA_Composite_Param::get_traditional_algorithm_id_by_id(): could not lookup algorithm OID of traditional algorithm as expected");
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

}  // namespace Botan
