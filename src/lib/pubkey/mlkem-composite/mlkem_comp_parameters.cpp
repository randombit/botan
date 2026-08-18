/*
 * ML-KEM Composite KEM Parameters
 * (C) 2026 Falko Strenzke, MTG AG
 *     2026 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/mlkem_comp_parameters.h>

#include <botan/asn1_obj.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/oids.h>
#include <botan/pss_params.h>
#include <botan/internal/fmt.h>
#include <botan/internal/oid_map.h>
#if defined(BOTAN_HAS_ECDH)
   #include <botan/ec_group.h>
#endif

#include <cstring>
#include <string_view>

namespace Botan {

const MLKEM_Composite_Param MLKEM_Composite_Param::mlkem_composite_registry[] = {

   MLKEM_Composite_Param(MLKEM_Composite_Param::id_t::MLKEM768_RSA2048_SHA3_256,
                         "MLKEM768-RSA2048-SHA3-256",
                         "MLKEM768-RSAOAEP2048",
                         "ML-KEM-768",
                         "RSA",
                         "OAEP(SHA-256)",
                         "",
                         2048),
   MLKEM_Composite_Param(MLKEM_Composite_Param::id_t::MLKEM768_RSA3072_SHA3_256,
                         "MLKEM768-RSA3072-SHA3-256",
                         "MLKEM768-RSAOAEP3072",
                         "ML-KEM-768",
                         "RSA",
                         "OAEP(SHA-256)",
                         "",
                         3072),
   MLKEM_Composite_Param(MLKEM_Composite_Param::id_t::MLKEM768_RSA4096_SHA3_256,
                         "MLKEM768-RSA4096-SHA3-256",
                         "MLKEM768-RSAOAEP4096",
                         "ML-KEM-768",
                         "RSA",
                         "OAEP(SHA-256)",
                         "",
                         4096),
   MLKEM_Composite_Param(
      MLKEM768_X25519_SHA3_256, "MLKEM768-X25519-SHA3-256", "\\.//^\\", "ML-KEM-768", "X25519", "", "", 255),
   MLKEM_Composite_Param(MLKEM_Composite_Param::id_t::MLKEM1024_RSA3072_SHA3_256,
                         "MLKEM1024-RSA3072-SHA3-256",
                         "MLKEM1024-RSAOAEP3072",
                         "ML-KEM-1024",
                         "RSA",
                         "OAEP(SHA-256)",
                         "",
                         3072),
   MLKEM_Composite_Param(MLKEM768_ECDH_P256_SHA3_256,
                         "MLKEM768-ECDH-P256-SHA3-256",
                         "MLKEM768-P256",
                         "ML-KEM-768",
                         "ECDH",
                         "",
                         "secp256r1",
                         256),
   MLKEM_Composite_Param(MLKEM768_ECDH_P384_SHA3_256,
                         "MLKEM768-ECDH-P384-SHA3-256",
                         "MLKEM768-P384",
                         "ML-KEM-768",
                         "ECDH",
                         "",
                         "secp384r1",
                         384),
   MLKEM_Composite_Param(MLKEM768_ECDH_brainpoolP256r1_SHA3_256,
                         "MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
                         "MLKEM768-BP256",
                         "ML-KEM-768",
                         "ECDH",
                         "",
                         "brainpool256r1",
                         256),
   MLKEM_Composite_Param(MLKEM1024_ECDH_P384_SHA3_256,
                         "MLKEM1024-ECDH-P384-SHA3-256",
                         "MLKEM1024-P384",
                         "ML-KEM-1024",
                         "ECDH",
                         "",
                         "secp384r1",
                         384),
   MLKEM_Composite_Param(MLKEM1024_ECDH_brainpoolP384r1_SHA3_256,
                         "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
                         "MLKEM1024-BP384",
                         "ML-KEM-1024",
                         "ECDH",
                         "",
                         "brainpool384r1",
                         384),
   MLKEM_Composite_Param(
      MLKEM1024_X448_SHA3_256, "MLKEM1024-X448-SHA3-256", "MLKEM1024-X448", "ML-KEM-1024", "X448", "", "", 224),
   MLKEM_Composite_Param(MLKEM1024_ECDH_P521_SHA3_256,
                         "MLKEM1024-ECDH-P521-SHA3-256",
                         "MLKEM1024-P521",
                         "ML-KEM-1024",
                         "ECDH",
                         "",
                         "secp521r1",
                         521)

};

// static
std::vector<MLKEM_Composite_Param> MLKEM_Composite_Param::all_param_sets() {
   std::vector<MLKEM_Composite_Param> result;
   for(const auto& param : mlkem_composite_registry) {
      result.push_back(param);
   }
   return result;
}

// static
std::vector<MLKEM_Composite_Param> MLKEM_Composite_Param::all_supported_param_sets() {
   std::vector<MLKEM_Composite_Param> result;
   for(const auto& param : mlkem_composite_registry) {
      if(param.is_supported()) {
         result.push_back(param);
      }
   }
   return result;
}

// static
std::optional<MLKEM_Composite_Param> MLKEM_Composite_Param::from_id_str(std::string_view id_str) {
   for(const auto& param : mlkem_composite_registry) {
      if(param.m_id_str == id_str) {
         return std::optional<MLKEM_Composite_Param>(param);
      }
   }
   return std::optional<MLKEM_Composite_Param>();
}

//static
std::optional<MLKEM_Composite_Param> MLKEM_Composite_Param::from_algo_id(const AlgorithmIdentifier& algo_id) {
   for(const auto& param : mlkem_composite_registry) {
      if(param.get_composite_algorithm_id() == algo_id) {
         return std::optional<MLKEM_Composite_Param>(param);
      }
   }
   return std::optional<MLKEM_Composite_Param>();
}

//static
MLKEM_Composite_Param MLKEM_Composite_Param::from_algo_id_or_throw(const AlgorithmIdentifier& algo_id) {
   const auto result = from_algo_id(algo_id);
   if(!result.has_value()) {
      throw Botan::Invalid_Argument("no parameter found for provided MLKEM composite algo id");
   }
   return result.value();
}

// static
MLKEM_Composite_Param MLKEM_Composite_Param::from_id_str_or_throw(std::string_view id_str) {
   const auto result = from_id_str(id_str);
   if(!result.has_value()) {
      throw Botan::Invalid_Argument("no parameter found for provided MLKEM composite id " + std::string(id_str));
   }
   return result.value();
}

// static
std::optional<MLKEM_Composite_Param> MLKEM_Composite_Param::from_id(MLKEM_Composite_Param::id_t id) {
   for(const auto& param : mlkem_composite_registry) {
      if(param.m_id == id) {
         return std::optional<MLKEM_Composite_Param>(param);
      }
   }
   return std::optional<MLKEM_Composite_Param>();
}

// static
MLKEM_Composite_Param MLKEM_Composite_Param::from_id_supported_or_throw(MLKEM_Composite_Param::id_t id) {
   const auto result = from_id(id);
   if(!result.has_value()) {
      throw Botan::Invalid_Argument("no parameter found for provided MLKEM composite id (enum)");
   }
   if(!result.value().is_supported()) {
      throw Not_Implemented("Parameter set " + result.value().id_str() +
                            " is not supported by Botan's build configuration");
   }
   return result.value();
}

MLKEM_Composite_Param::MLKEM_Composite_Param(id_t the_id,
                                             std::string_view the_id_str,
                                             std::string_view the_label,
                                             std::string_view the_mlkem_variant,
                                             std::string_view the_traditional_algorithm,
                                             std::string_view the_traditional_padding,
                                             std::string_view the_curve,
                                             uint32_t the_traditional_key_size) noexcept :
      m_id_str(the_id_str),
      m_label(the_label),
      m_mlkem_variant(the_mlkem_variant),
      m_traditional_algorithm(the_traditional_algorithm),
      m_traditional_padding(the_traditional_padding),
      m_curve(the_curve),
      m_id(the_id),
      m_traditional_key_size(the_traditional_key_size) {}

size_t MLKEM_Composite_Param::mlkem_pubkey_size() const {
   if(m_mlkem_variant == "ML-KEM-768") {
      return 1184;
   }
   return 1568;  // must be ML-KEM-1024
}

AlgorithmIdentifier MLKEM_Composite_Param::get_composite_algorithm_id() const {
   std::optional<OID> oid;
   oid = OID::from_name(m_id_str);
   if(!oid.has_value()) {
      throw Botan::Internal_Error(fmt("could not look up own MLKEM Composite OID for ID-string '{}'", m_id_str));
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

AlgorithmIdentifier MLKEM_Composite_Param::get_mlkem_algorithm_id() const {
   const auto oid = OID::from_string(m_mlkem_variant);
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

AlgorithmIdentifier MLKEM_Composite_Param::get_traditional_algorithm_id() const {
   std::optional<OID> oid;
   if(this->m_traditional_algorithm == "ECDH") {
      oid = OID::from_name(std::string("ECDH"));
#if defined(BOTAN_HAS_ECDH)
      if(oid.has_value()) {
         // Carry the curve mandated by the composite parameter set as the algorithm
         // parameters. The EC key decoding routines check the curve encoded within
         // a private key against these parameters, so that a component key on any
         // other curve is rejected.
         return AlgorithmIdentifier(oid.value(), EC_Group::from_name(m_curve).DER_encode());
      }
#endif
   } else {
      oid = OID::from_name(this->m_traditional_algorithm);
   }
   if(!oid.has_value()) {
      throw Botan::Internal_Error(
         "MLKEM_Composite_Param::get_traditional_algorithm_id_by_id(): could not lookup algorithm OID of traditional algorithm as expected");
   }
   return AlgorithmIdentifier(oid.value(), AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
}

std::string MLKEM_Composite_Param::get_traditional_algo_param_str() const {
   if(this->m_traditional_algorithm == "RSA") {
      return std::to_string(m_traditional_key_size);
   }
   return "";
}

OID MLKEM_Composite_Param::object_identifier() const {
   return OID_Map::global_registry().str2oid(this->m_id_str);
}

bool MLKEM_Composite_Param::is_supported() const {
   bool result = false;
#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_OAEP)
   result = result || m_id == MLKEM768_RSA2048_SHA3_256 || m_id == MLKEM768_RSA3072_SHA3_256 ||
            m_id == MLKEM768_RSA4096_SHA3_256 || m_id == MLKEM1024_RSA3072_SHA3_256;
#endif
#if defined(BOTAN_HAS_ECDH)
   #if defined(BOTAN_HAS_PCURVES_GENERIC) || defined(BOTAN_HAS_PCURVES_SECP256R1)
   result = result || m_id == MLKEM768_ECDH_P256_SHA3_256;
   #endif
   #if defined(BOTAN_HAS_PCURVES_GENERIC) || defined(BOTAN_HAS_PCURVES_SECP384R1)
   result = result || m_id == MLKEM768_ECDH_P384_SHA3_256 || m_id == MLKEM1024_ECDH_P384_SHA3_256;
   #endif
   #if defined(BOTAN_HAS_PCURVES_GENERIC) || defined(BOTAN_HAS_PCURVES_BRAINPOOL256R1)
   result = result || m_id == MLKEM768_ECDH_brainpoolP256r1_SHA3_256;
   #endif
   #if defined(BOTAN_HAS_PCURVES_GENERIC) || defined(BOTAN_HAS_PCURVES_BRAINPOOL384R1)
   result = result || m_id == MLKEM1024_ECDH_brainpoolP384r1_SHA3_256;
   #endif
   #if defined(BOTAN_HAS_PCURVES_GENERIC) || defined(BOTAN_HAS_PCURVES_SECP521R1)
   result = result || m_id == MLKEM1024_ECDH_P521_SHA3_256;
   #endif
#endif
#if defined(BOTAN_HAS_X25519)
   result = result || m_id == MLKEM768_X25519_SHA3_256;
#endif
#if defined(BOTAN_HAS_X448)
   result = result || m_id == MLKEM1024_X448_SHA3_256;
#endif
   return result;
}

}  // namespace Botan
