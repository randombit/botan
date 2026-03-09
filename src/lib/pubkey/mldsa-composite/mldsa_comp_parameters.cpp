
#include "botan/exceptn.h"
#include "botan/hex.h"
#include "botan/internal/fmt.h"
#include <botan/asn1_obj.h>
#include <botan/mldsa_comp_parameters.h>
#include <botan/oids.h>
#include <botan/pss_params.h>
#include <cstring>
#include <string_view>

#include <iostream>

namespace Botan {

static const MLDSA_Composite_Param mldsa_composite_registry[] = {
   {.id = MLDSA_Composite_Param::id_t::MLDSA44_RSA2048_PSS_SHA256,
    .id_str = "MLDSA44-RSA2048-PSS-SHA256",
    .label = "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
    .prehash_func = "SHA-256",
    .mldsa_variant = DilithiumMode::ML_DSA_4x4,
    .mldsa_oid_str = "2.16.840.1.101.3.4.3.17",
    .traditional_algoritm = "RSA",
    .traditional_padding = "PSS(SHA-256,MGF1,32)",
    .curve = "",
    .mldsa_pubkey_size = 1312,
    .traditional_key_size = 2048}  // namespace Botan

   ,
   {.id = MLDSA_Composite_Param::id_t::MLDSA44_RSA2048_PKCS15_SHA256,
    .id_str = "MLDSA44-RSA2048-PKCS15-SHA256",
    .label = "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
    .prehash_func = "SHA-256",
    .mldsa_variant = DilithiumMode::ML_DSA_4x4,
    .mldsa_oid_str = "2.16.840.1.101.3.4.3.17",
    .traditional_algoritm = "RSA",
    .traditional_padding = "PKCS1v15(SHA-256)",
    .curve = "",
    .mldsa_pubkey_size = 1312,
    .traditional_key_size = 2048}  // namespace Botan

   ,
   {.id = MLDSA_Composite_Param::id_t::MLDSA44_Ed25519_SHA512,
    .id_str = "MLDSA44-Ed25519-SHA512",
    .label = "COMPSIG-MLDSA44-Ed25519-SHA512",
    .prehash_func = "SHA-512",
    .mldsa_variant = DilithiumMode::ML_DSA_4x4,
    .mldsa_oid_str = "2.16.840.1.101.3.4.3.17",
    .traditional_algoritm = "Ed25519",
    .traditional_padding = "",
    .curve = "",
    .mldsa_pubkey_size = 1312,
    .traditional_key_size = 255},
   {
      .id = MLDSA_Composite_Param::id_t::MLDSA44_ECDSA_P256_SHA256,
      .id_str = "MLDSA44-ECDSA-P256-SHA256",
      .label = "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
      .prehash_func = "SHA-256",
      .mldsa_variant = DilithiumMode::ML_DSA_4x4,
      .mldsa_oid_str = "2.16.840.1.101.3.4.3.17",
      .traditional_algoritm = "ECDSA",
      .traditional_padding = "SHA-256",
      .curve = "secp256r1",
      .mldsa_pubkey_size = 1312,
      .traditional_key_size = 256  // NEEDED?
   }};

std::vector<MLDSA_Composite_Param> MLDSA_Composite_Param::all_param_sets() {
   std::vector<MLDSA_Composite_Param> result;
   for(const auto& param : mldsa_composite_registry) {
      result.push_back(param);
   }
   return result;
}

// static
std::optional<MLDSA_Composite_Param> MLDSA_Composite_Param::from_id_str(std::string_view id_str) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.id_str == id_str) {
         return std::optional<MLDSA_Composite_Param>(param);
      }
   }
   return std::optional<MLDSA_Composite_Param>();
}

//static
std::optional<MLDSA_Composite_Param> MLDSA_Composite_Param::from_algo_id(const AlgorithmIdentifier& algo_id) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.get_composite_algorithm_id() == algo_id) {
         return std::optional<MLDSA_Composite_Param>(param);
      }
   }
   return std::optional<MLDSA_Composite_Param>();
}

//static
MLDSA_Composite_Param MLDSA_Composite_Param::from_algo_id_or_throw(const AlgorithmIdentifier& algo_id) {
   const auto result = from_algo_id(algo_id);
   if(!result.has_value()) {
      throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite algo id");
   }
   return result.value();
}

// static
MLDSA_Composite_Param MLDSA_Composite_Param::from_id_str_or_throw(std::string_view id_str) {
   const auto result = from_id_str(id_str);
   if(!result.has_value()) {
      throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite id " + std::string(id_str));
   }
   return result.value();
}

// static
std::optional<MLDSA_Composite_Param> MLDSA_Composite_Param::from_id(MLDSA_Composite_Param::id_t id) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.id == id) {
         return std::optional<MLDSA_Composite_Param>(param);
      }
   }
   return std::optional<MLDSA_Composite_Param>();
}

// static
MLDSA_Composite_Param MLDSA_Composite_Param::from_id_or_throw(MLDSA_Composite_Param::id_t id) {
   const auto result = from_id(id);
   if(!result.has_value()) {
      throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite id (enum)");
   }
   return result.value();
}

std::string MLDSA_Composite_Param::mldsa_param_str() const {
   std::string label_str(label);
   std::vector<uint8_t> label_vec(label_str.begin(), label_str.end());
   return std::string("Pure,Randomized,ctx_hex=") + hex_encode(label_vec);
}

size_t MLDSA_Composite_Param::traditional_signature_size() const {
   if(0 == std::strcmp(traditional_algoritm, "RSA")) {
      return traditional_key_size;
   } else if(0 == std::strcmp(traditional_algoritm, "Ed25519")) {
      return 255;
   }
   throw Botan::Exception(
      "TODO: MLDSA_Composite_Param::traditional_signature_size(): not implemented for parameters other than RSA");
}

size_t MLDSA_Composite_Param::mldsa_signature_size() const {
   if(this->mldsa_variant == DilithiumMode::ML_DSA_4x4) {
      return 2420;
   } else if(this->mldsa_variant == DilithiumMode::ML_DSA_6x5) {
      return 3309;
   } else if(this->mldsa_variant == DilithiumMode::ML_DSA_8x7) {
      return 4627;
   }
   throw Botan::Internal_Error("MLDSA_Composite_Param::mldsa_signature_size() encountered unknown ML-DSA variant ");
}

AlgorithmIdentifier MLDSA_Composite_Param::get_composite_algorithm_id() const {
   std::optional<OID> oid;
   oid = OID::from_name(id_str);
   if(!oid.has_value()) {
      throw Botan::Internal_Error(fmt("could not look up own MLDSA Composite ID '{}' for OID", id_str));
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
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
   if(0 == std::strcmp(this->traditional_algoritm, "ECDSA")) {
      oid = OID::from_name(std::string("ECDSA/") + prehash_func);
   } else {
      oid = OID::from_name(this->traditional_algoritm);
   }
   if(!oid.has_value()) {
      throw Botan::Internal_Error(
         "MLDSA_Composite_Param::get_traditional_algorithm_id_by_id(): could not lookup algorithm OID of traditional algorithm as expected");
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

std::string MLDSA_Composite_Param::get_traditional_algo_param_str() const {
   if(0 == strcmp(this->traditional_algoritm, "RSA")) {
      return std::to_string(traditional_key_size);
   } else if(0 == strcmp(this->traditional_algoritm, "Ed25519")) {
      return "";
   }
   throw Botan::Invalid_Argument(
      "TODO: MLDSA_Composite_Param::get_traditional_algo_param_str() not implemented for ECC or other");
}

}  // namespace Botan
