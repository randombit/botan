/*
* TPM 2 algorithm mappings
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_ALGORITHM_MAPPINGS_H_
#define BOTAN_TPM2_ALGORITHM_MAPPINGS_H_

#include <botan/types.h>

#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <tss2/tss2_tpm2_types.h>

namespace Botan {

class OID;

}

namespace Botan::TPM2 {

[[nodiscard]] std::optional<TPM2_ALG_ID> asymmetric_algorithm_botan_to_tss2(std::string_view algo_name) noexcept;

/**
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *          otherwise std::nullopt
 */
[[nodiscard]] std::optional<TPMI_ALG_HASH> hash_algo_botan_to_tss2(std::string_view hash_name) noexcept;

/**
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *         otherwise throws Lookup_Error
  */
[[nodiscard]] TPMI_ALG_HASH get_tpm2_hash_type(std::string_view hash_name);

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise std::nullopt
 */
[[nodiscard]] std::optional<std::string> hash_algo_tss2_to_botan(TPMI_ALG_HASH hash_id);

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise throws Invalid_State
 */
[[nodiscard]] std::string get_botan_hash_name(TPM2_ALG_ID hash_id);

[[nodiscard]] std::optional<std::string> block_cipher_tss2_to_botan(TPMI_ALG_SYM cipher_id, TPM2_KEY_BITS key_bits);

[[nodiscard]] std::optional<std::pair<TPMI_ALG_SYM, TPM2_KEY_BITS>> block_cipher_botan_to_tss2(
   std::string_view cipher_name) noexcept;

[[nodiscard]] std::optional<std::string> cipher_mode_tss2_to_botan(TPMI_ALG_SYM_MODE mode_id);

[[nodiscard]] std::optional<std::string> curve_id_tss2_to_botan(TPMI_ECC_CURVE mode_id);

[[nodiscard]] std::optional<size_t> curve_id_order_byte_size(TPMI_ECC_CURVE curve_id);

[[nodiscard]] std::optional<TPM2_ECC_CURVE> get_tpm2_curve_id(const OID& curve_oid);

[[nodiscard]] std::optional<TPMI_ALG_SYM_MODE> cipher_mode_botan_to_tss2(std::string_view mode_name) noexcept;

/**
 * @returns a Botan cipher mode name string if the @p cipher_id, @p key_bits and
 *          @p mode_name are known, otherwise std::nullopt
 */
[[nodiscard]] std::optional<std::string> cipher_tss2_to_botan(TPMT_SYM_DEF cipher_def);

[[nodiscard]] std::optional<TPMT_SYM_DEF> cipher_botan_to_tss2(std::string_view algo_name);

[[nodiscard]] TPMT_SYM_DEF get_tpm2_sym_cipher_spec(std::string_view algo_name);

[[nodiscard]] std::optional<TPMI_ALG_SIG_SCHEME> rsa_signature_padding_botan_to_tss2(
   std::string_view padding_name) noexcept;

[[nodiscard]] std::optional<TPMT_SIG_SCHEME> rsa_signature_scheme_botan_to_tss2(std::string_view name);

[[nodiscard]] std::optional<TPMI_ALG_ASYM_SCHEME> rsa_encryption_padding_botan_to_tss2(std::string_view name) noexcept;

[[nodiscard]] std::optional<TPMT_RSA_DECRYPT> rsa_encryption_scheme_botan_to_tss2(std::string_view padding);

}  // namespace Botan::TPM2

#endif
