/**
* Ounsworth Internal Helpers
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/assert.h>
#include <botan/internal/ounsworth_internal.h>

#include <algorithm>

namespace Botan {
namespace {
Ounsworth::Sub_Algo_Type sub_algo_type_from_string(std::string_view algo) {
#ifdef BOTAN_HAS_KYBER
   if(algo == "Kyber-512-r3") {
      return Ounsworth::Sub_Algo_Type::Kyber512_R3;
   }
   if(algo == "Kyber-768-r3") {
      return Ounsworth::Sub_Algo_Type::Kyber768_R3;
   }
   if(algo == "Kyber-1024-r3") {
      return Ounsworth::Sub_Algo_Type::Kyber1024_R3;
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM_SHAKE
   if(algo == "FrodoKEM-640-SHAKE") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM640_SHAKE;
   }
   if(algo == "FrodoKEM-976-SHAKE") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM976_SHAKE;
   }
   if(algo == "FrodoKEM-1344-SHAKE") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM1344_SHAKE;
   }
#endif
#ifdef BOTAN_HAS_FRODOKEM_AES
   if(algo == "FrodoKEM-640-AES") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM640_AES;
   }
   if(algo == "FrodoKEM-976-AES") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM976_AES;
   }
   if(algo == "FrodoKEM-1344-AES") {
      return Ounsworth::Sub_Algo_Type::FrodoKEM1344_AES;
   }
#endif
#ifdef BOTAN_HAS_X25519
   if(algo == "X25519") {
      return Ounsworth::Sub_Algo_Type::X25519;
   }
#endif
#ifdef BOTAN_HAS_X448
   if(algo == "X448") {
      return Ounsworth::Sub_Algo_Type::X448;
   }
#endif
#ifdef BOTAN_HAS_ECDH
   if(algo == "ECDH-secp192r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp192R1;
   }
   if(algo == "ECDH-secp224r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp224R1;
   }
   if(algo == "ECDH-secp256r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp256R1;
   }
   if(algo == "ECDH-secp384r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp384R1;
   }
   if(algo == "ECDH-secp521r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Secp521R1;
   }
   if(algo == "ECDH-brainpool256r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Brainpool256R1;
   }
   if(algo == "ECDH-brainpool384r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Brainpool384R1;
   }
   if(algo == "ECDH-brainpool512r1") {
      return Ounsworth::Sub_Algo_Type::ECDH_Brainpool512R1;
   }
#endif
   throw Invalid_Argument(fmt("Unknown Ounsworth sub-algorithm type '{}'", algo));
}

Ounsworth::Kdf::Option kdf_type_from_string(std::string_view type) {
   if(type == "KMAC-128") {
      return Ounsworth::Kdf::Option::KMAC128;
   }
   if(type == "KMAC-256") {
      return Ounsworth::Kdf::Option::KMAC256;
   }
   if(type == "SHA3-256") {
      return Ounsworth::Kdf::Option::SHA3_256;
   }
   if(type == "SHA3-512") {
      return Ounsworth::Kdf::Option::SHA3_512;
   }
   throw Invalid_Argument(fmt("Unknown Ounsworth KDF type '{}'", type));
}

std::pair<std::vector<Ounsworth::Sub_Algo_Type>, Ounsworth::Kdf> sub_algos_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id) {
   return parse_ounsworth_mode_str(alg_id.oid().to_formatted_string());
}

template <typename InfoType>
std::pair<std::vector<InfoType>, Ounsworth::Kdf> info_and_kdf_from_alg_id(const AlgorithmIdentifier& alg_id)
   requires requires(Ounsworth::Sub_Algo_Type sub_algo) { InfoType{sub_algo}; }
{
   auto [sub_algo_types, kdf] = sub_algos_and_kdf_from_alg_id(alg_id);
   std::vector<InfoType> info;
   std::transform(sub_algo_types.begin(), sub_algo_types.end(), std::back_inserter(info), [](const auto& sub_algo) {
      return InfoType{sub_algo};
   });
   return {std::move(info), kdf};
}
}  // namespace

std::string ounsworth_algorithm_name() {
   return "OunsworthKEMCombiner";
}

// Example: "OunsworthKEMCombiner/Kyber-512-r3/FrodoKEM-640-SHAKE/KMAC-128"
std::pair<std::vector<Ounsworth::Sub_Algo_Type>, Ounsworth::Kdf> parse_ounsworth_mode_str(std::string_view mode_str) {
   const std::string prefix = ounsworth_algorithm_name();
   const std::vector<std::string> parts = split_on(mode_str, '/');
   BOTAN_ARG_CHECK(parts.size() >= 4, "Ounsworth mode string must contain at least 4 parts");
   BOTAN_ARG_CHECK(parts[0] == prefix, "Invalid Ounsworth mode string");

   // Parse sub-algorithms
   std::vector<Ounsworth::Sub_Algo_Type> sub_algo_types;
   std::transform(parts.begin() + 1, parts.end() - 1, std::back_inserter(sub_algo_types), [](const std::string& part) {
      return sub_algo_type_from_string(part);
   });
   // Parse KDF
   const Ounsworth::Kdf kdf(kdf_type_from_string(parts.back()));

   return {sub_algo_types, kdf};
}

std::pair<std::vector<Ounsworth::PublicKeyImportInfo>, Ounsworth::Kdf> pk_import_info_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id) {
   return info_and_kdf_from_alg_id<Ounsworth::PublicKeyImportInfo>(alg_id);
}

std::pair<std::vector<Ounsworth::PrivateKeyImportInfo>, Ounsworth::Kdf> sk_import_info_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id) {
   return info_and_kdf_from_alg_id<Ounsworth::PrivateKeyImportInfo>(alg_id);
}

std::pair<std::vector<Ounsworth::PrivateKeyGenerationInfo>, Ounsworth::Kdf> sk_gen_info_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id) {
   return info_and_kdf_from_alg_id<Ounsworth::PrivateKeyGenerationInfo>(alg_id);
}
}  // namespace Botan
