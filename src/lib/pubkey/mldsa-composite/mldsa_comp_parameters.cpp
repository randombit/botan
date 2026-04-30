/*
 * ML-DSA Composite Signature Schemes
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/mldsa_comp_parameters.h>

#include <botan/asn1_obj.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/oids.h>
#include <botan/pss_params.h>
#include <botan/internal/fmt.h>
#include <cstring>
#include <string_view>

namespace Botan {

const MLDSA_Composite_Param MLDSA_Composite_Param::mldsa_composite_registry[] = {

#if defined(BOTAN_HAS_RSA)
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA44_RSA2048_PKCS15_SHA256,
                         "MLDSA44-RSA2048-PKCS15-SHA256",
                         "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
                         "SHA-256",
                         DilithiumMode::ML_DSA_4x4,
                         "RSA",
                         "PKCS1v15(SHA-256)",
                         "",
                         2048),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_RSA3072_PKCS15_SHA512,
                         "MLDSA65-RSA3072-PKCS15-SHA512",
                         "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "RSA",
                         "PKCS1v15(SHA-256)",
                         "",
                         3072),
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_RSA4096_PKCS15_SHA512,
                         "MLDSA65-RSA4096-PKCS15-SHA512",
                         "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "RSA",
                         "PKCS1v15(SHA-384)",
                         "",
                         4096),
#endif

#if defined(BOTAN_HAS_PSS)
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA44_RSA2048_PSS_SHA256,
                         "MLDSA44-RSA2048-PSS-SHA256",
                         "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
                         "SHA-256",
                         DilithiumMode::ML_DSA_4x4,
                         "RSA",
                         "PSS(SHA-256,MGF1,32)",
                         "",
                         2048),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_RSA3072_PSS_SHA512,
                         "MLDSA65-RSA3072-PSS-SHA512",
                         "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "RSA",
                         "PSS(SHA-256,MGF1,32)",
                         "",
                         3072),
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_RSA4096_PSS_SHA512,
                         "MLDSA65-RSA4096-PSS-SHA512",
                         "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "RSA",
                         "PSS(SHA-384,MGF1,48)",
                         "",
                         4096),
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA87_RSA3072_PSS_SHA512,
                         "MLDSA87-RSA3072-PSS-SHA512",
                         "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_8x7,
                         "RSA",
                         "PSS(SHA-256,MGF1,32)",
                         "",
                         3072),
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA87_RSA4096_PSS_SHA512,
                         "MLDSA87-RSA4096-PSS-SHA512",
                         "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_8x7,
                         "RSA",
                         "PSS(SHA-384,MGF1,48)",
                         "",
                         4096),
#endif
#if defined(BOTAN_HAS_ECDSA)

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA44_ECDSA_P256_SHA256,
                         "MLDSA44-ECDSA-P256-SHA256",
                         "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
                         "SHA-256",
                         DilithiumMode::ML_DSA_4x4,
                         "ECDSA",
                         "SHA-256",
                         "secp256r1",
                         0),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_ECDSA_P256_SHA512,
                         "MLDSA65-ECDSA-P256-SHA512",
                         "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "ECDSA",
                         "SHA-256",
                         "secp256r1",
                         0),
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_ECDSA_P384_SHA512,
                         "MLDSA65-ECDSA-P384-SHA512",
                         "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "ECDSA",
                         "SHA-384",
                         "secp384r1",
                         0),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_ECDSA_brainpoolP256r1_SHA512,
                         "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
                         "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "ECDSA",
                         "SHA-256",
                         "brainpool256r1",
                         0),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA87_ECDSA_P384_SHA512,
                         "MLDSA87-ECDSA-P384-SHA512",
                         "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_8x7,
                         "ECDSA",
                         "SHA-384",
                         "secp384r1",
                         0),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA87_ECDSA_brainpoolP384r1_SHA512,
                         "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
                         "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_8x7,
                         "ECDSA",
                         "SHA-384",
                         "brainpool384r1",
                         0),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA87_ECDSA_P521_SHA512,
                         "MLDSA87-ECDSA-P521-SHA512",
                         "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_8x7,
                         "ECDSA",
                         "SHA-512",
                         "secp521r1",
                         0),
#endif

#if defined(BOTAN_HAS_ED25519)
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA44_Ed25519_SHA512,
                         "MLDSA44-Ed25519-SHA512",
                         "COMPSIG-MLDSA44-Ed25519-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_4x4,
                         "Ed25519",
                         "",
                         "",
                         0),

   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA65_Ed25519_SHA512,
                         "MLDSA65-Ed25519-SHA512",
                         "COMPSIG-MLDSA65-Ed25519-SHA512",
                         "SHA-512",
                         DilithiumMode::ML_DSA_6x5,
                         "Ed25519",
                         "",
                         "",
                         0),
#endif
#if defined(BOTAN_HAS_ED448)
   MLDSA_Composite_Param(MLDSA_Composite_Param::id_t::MLDSA87_Ed448_SHAKE256,
                         "MLDSA87-Ed448-SHAKE256",
                         "COMPSIG-MLDSA87-Ed448-SHAKE256",
                         "SHAKE-256(512)",
                         DilithiumMode::ML_DSA_8x7,
                         "Ed448",
                         "",
                         "",
                         0),
#endif

};

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
      if(param.m_id_str == id_str) {
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
      if(param.m_id == id) {
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

MLDSA_Composite_Param::MLDSA_Composite_Param(id_t the_id,
                                             const char* the_id_str,
                                             const char* the_label,
                                             const char* the_prehash_func,
                                             DilithiumMode::Mode the_mldsa_variant,
                                             const char* the_traditional_algorithm,
                                             const char* the_traditional_padding,
                                             const char* the_curve,
                                             uint32_t the_traditional_key_size) noexcept :
      m_id_str(the_id_str),
      m_label(the_label),
      m_prehash_func(the_prehash_func),
      m_traditional_algorithm(the_traditional_algorithm),
      m_traditional_padding(the_traditional_padding),
      m_curve(the_curve),
      m_id(the_id),
      m_traditional_key_size(the_traditional_key_size),
      m_mldsa_variant(the_mldsa_variant) {}

const char* MLDSA_Composite_Param::mldsa_oid_str() const {
   if(m_mldsa_variant == DilithiumMode::ML_DSA_4x4) {
      return "2.16.840.1.101.3.4.3.17";
   } else if(m_mldsa_variant == DilithiumMode::ML_DSA_6x5) {
      return "2.16.840.1.101.3.4.3.18";
   } else if(m_mldsa_variant == DilithiumMode::ML_DSA_8x7) {
      return "2.16.840.1.101.3.4.3.19";
   }
   throw Internal_Error("invalid MLDSA mode in MLDSA composite parameters");
}

size_t MLDSA_Composite_Param::mldsa_pubkey_size() const {
   if(m_mldsa_variant == DilithiumMode::ML_DSA_4x4) {
      return 1312;
   } else if(m_mldsa_variant == DilithiumMode::ML_DSA_6x5) {
      return 1952;
   }
   return 2592;  // must be ML-DSA-87
}

std::string MLDSA_Composite_Param::mldsa_param_str() const {
   std::string label_str(m_label);
   std::vector<uint8_t> label_vec(label_str.begin(), label_str.end());
   return std::string("Pure,Randomized,ctx_hex=") + hex_encode(label_vec);
}

size_t MLDSA_Composite_Param::mldsa_signature_size() const {
   if(this->m_mldsa_variant == DilithiumMode::ML_DSA_4x4) {
      return 2420;
   } else if(this->m_mldsa_variant == DilithiumMode::ML_DSA_6x5) {
      return 3309;
   } else if(this->m_mldsa_variant == DilithiumMode::ML_DSA_8x7) {
      return 4627;
   }
   throw Botan::Internal_Error("MLDSA_Composite_Param::mldsa_signature_size() encountered unknown ML-DSA variant ");
}

AlgorithmIdentifier MLDSA_Composite_Param::get_composite_algorithm_id() const {
   std::optional<OID> oid;
   oid = OID::from_name(m_id_str);
   if(!oid.has_value()) {
      throw Botan::Internal_Error(fmt("could not look up own MLDSA Composite ID '{}' for OID", m_id_str));
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

AlgorithmIdentifier MLDSA_Composite_Param::get_mldsa_algorithm_id() const {
   const OID oid(this->mldsa_oid_str());
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

AlgorithmIdentifier MLDSA_Composite_Param::get_traditional_algorithm_id() const {
   std::optional<OID> oid;
   if(0 == std::strcmp(this->m_traditional_algorithm, "ECDSA")) {
      oid = OID::from_name(std::string("ECDSA/") + m_prehash_func);
   } else {
      oid = OID::from_name(this->m_traditional_algorithm);
   }
   if(!oid.has_value()) {
      throw Botan::Internal_Error(
         "MLDSA_Composite_Param::get_traditional_algorithm_id_by_id(): could not lookup algorithm OID of traditional algorithm as expected");
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

std::string MLDSA_Composite_Param::get_traditional_algo_param_str() const {
   if(0 == strcmp(this->m_traditional_algorithm, "RSA")) {
      return std::to_string(m_traditional_key_size);
   }
   return "";
}

}  // namespace Botan
