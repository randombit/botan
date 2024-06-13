/**
* Ounsworth Internal Helpers
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OUNSWORTH_INTERNAL_H_
#define BOTAN_OUNSWORTH_INTERNAL_H_

#include <botan/ounsworth_mode.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

namespace Botan {

/// @returns the name of the Ounsworth algorithm
std::string ounsworth_algorithm_name();

/// Example: "OunsworthKEMCombiner/Kyber-512-r3/FrodoKEM-640-SHAKE/KMAC-128"
std::pair<std::vector<Ounsworth::Sub_Algo_Type>, Ounsworth::Kdf> parse_ounsworth_mode_str(std::string_view mode_str);

/// @returns (PkImportInfo, Kdf) pair from the given AlgorithmIdentifier
std::pair<std::vector<Ounsworth::PublicKeyImportInfo>, Ounsworth::Kdf> pk_import_info_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id);

/// @returns (SkImportInfo, Kdf) pair from the given AlgorithmIdentifier
std::pair<std::vector<Ounsworth::PrivateKeyImportInfo>, Ounsworth::Kdf> sk_import_info_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id);

/// @returns (PkGenInfo, Kdf) pair from the given AlgorithmIdentifier
std::pair<std::vector<Ounsworth::PrivateKeyGenerationInfo>, Ounsworth::Kdf> sk_gen_info_and_kdf_from_alg_id(
   const AlgorithmIdentifier& alg_id);

}  // namespace Botan

#endif  // BOTAN_OUNSWORTH_INTERNAL_H_
