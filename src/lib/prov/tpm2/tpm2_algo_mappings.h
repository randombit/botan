/*
* TPM 2 algorithm mappings
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_ALGORITHM_MAPPINGS_H_
#define BOTAN_TPM2_ALGORITHM_MAPPINGS_H_

#include <botan/asn1_obj.h>
#include <botan/exceptn.h>

#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

#include <optional>
#include <string>
#include <string_view>

#include <tss2/tss2_tpm2_types.h>

namespace Botan::TPM2 {

[[nodiscard]] inline std::optional<TPM2_ALG_ID> asymmetric_algorithm_botan_to_tss2(
   std::string_view algo_name) noexcept {
   if(algo_name == "RSA") {
      return TPM2_ALG_RSA;
   } else if(algo_name == "ECC") {
      return TPM2_ALG_ECC;
   } else if(algo_name == "ECDSA") {
      return TPM2_ALG_ECDSA;
   } else if(algo_name == "ECDH") {
      return TPM2_ALG_ECDH;
   } else if(algo_name == "ECDAA") {
      return TPM2_ALG_ECDAA;
   } else {
      return std::nullopt;
   }
}

/**
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *          otherwise std::nullopt
 */
[[nodiscard]] inline std::optional<TPMI_ALG_HASH> hash_algo_botan_to_tss2(std::string_view hash_name) noexcept {
   if(hash_name == "SHA-1") {
      return TPM2_ALG_SHA1;
   } else if(hash_name == "SHA-256") {
      return TPM2_ALG_SHA256;
   } else if(hash_name == "SHA-384") {
      return TPM2_ALG_SHA384;
   } else if(hash_name == "SHA-512") {
      return TPM2_ALG_SHA512;
   } else if(hash_name == "SHA-3(256)") {
      return TPM2_ALG_SHA3_256;
   } else if(hash_name == "SHA-3(384)") {
      return TPM2_ALG_SHA3_384;
   } else if(hash_name == "SHA-3(512)") {
      return TPM2_ALG_SHA3_512;
   } else if(hash_name == "SM3") {
      return TPM2_ALG_SM3_256;
   } else {
      return std::nullopt;
   }
}

/**
 * @returns a TPMI_ALG_HASH value if the @p hash_name is known,
 *         otherwise throws Lookup_Error
  */
[[nodiscard]] inline TPMI_ALG_HASH get_tpm2_hash_type(std::string_view hash_name) {
   if(auto hash_id = hash_algo_botan_to_tss2(hash_name)) {
      return hash_id.value();
   }

   throw Lookup_Error("TPM 2.0 Hash", hash_name);
}

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise std::nullopt
 */
[[nodiscard]] inline std::optional<std::string> hash_algo_tss2_to_botan(TPMI_ALG_HASH hash_id) noexcept {
   switch(hash_id) {
      case TPM2_ALG_SHA1:
         return "SHA-1";
      case TPM2_ALG_SHA256:
         return "SHA-256";
      case TPM2_ALG_SHA384:
         return "SHA-384";
      case TPM2_ALG_SHA512:
         return "SHA-512";
      case TPM2_ALG_SHA3_256:
         return "SHA-3(256)";
      case TPM2_ALG_SHA3_384:
         return "SHA-3(384)";
      case TPM2_ALG_SHA3_512:
         return "SHA-3(512)";
      case TPM2_ALG_SM3_256:
         return "SM3";
      default:  // TPMI_ALG_HASH is not an enum
         return std::nullopt;
   }
}

/**
 * @returns a Botan hash name string if the @p hash_id value is known,
 *          otherwise throws Invalid_State
 */
[[nodiscard]] inline std::string get_botan_hash_name(TPM2_ALG_ID hash_id) {
   if(auto hash_name = hash_algo_tss2_to_botan(hash_id)) {
      return hash_name.value();
   }

   throw Invalid_State("TPM 2.0 hash object with unexpected hash type");
}

[[nodiscard]] inline std::optional<std::string> block_cipher_tss2_to_botan(TPMI_ALG_SYM cipher_id,
                                                                           TPM2_KEY_BITS key_bits) noexcept {
   switch(cipher_id) {
      case TPM2_ALG_AES:
         if(key_bits == 128) {
            return "AES-128";
         } else if(key_bits == 192) {
            return "AES-192";
         } else if(key_bits == 256) {
            return "AES-256";
         }
         break;

      case TPM2_ALG_SM4:
         if(key_bits == 128) {
            return "SM4";
         }
         break;

      case TPM2_ALG_CAMELLIA:
         if(key_bits == 128) {
            return "Camellia-128";
         } else if(key_bits == 192) {
            return "Camellia-192";
         } else if(key_bits == 256) {
            return "Camellia-256";
         }
         break;

      case TPM2_ALG_TDES:
         return "3DES";

      default:
         break;
   }

   return std::nullopt;
}

[[nodiscard]] inline std::optional<std::pair<TPMI_ALG_SYM, TPM2_KEY_BITS>> block_cipher_botan_to_tss2(
   std::string_view cipher_name) noexcept {
   if(cipher_name == "AES-128") {
      return std::pair{TPM2_ALG_AES, 128};
   } else if(cipher_name == "AES-192") {
      return std::pair{TPM2_ALG_AES, 192};
   } else if(cipher_name == "AES-256") {
      return std::pair{TPM2_ALG_AES, 256};
   } else if(cipher_name == "SM4") {
      return std::pair{TPM2_ALG_SM4, 128};
   } else if(cipher_name == "Camellia-128") {
      return std::pair{TPM2_ALG_CAMELLIA, 128};
   } else if(cipher_name == "Camellia-192") {
      return std::pair{TPM2_ALG_CAMELLIA, 192};
   } else if(cipher_name == "Camellia-256") {
      return std::pair{TPM2_ALG_CAMELLIA, 256};
   } else if(cipher_name == "3DES") {
      return std::pair{TPM2_ALG_TDES, 168};
   } else {
      return {};
   }
}

[[nodiscard]] inline std::optional<std::string> cipher_mode_tss2_to_botan(TPMI_ALG_SYM_MODE mode_id) {
   switch(mode_id) {
      case TPM2_ALG_CFB:
         return "CFB";
      case TPM2_ALG_CBC:
         return "CBC";
      case TPM2_ALG_ECB:
         return "ECB";
      case TPM2_ALG_OFB:
         return "OFB";
      case TPM2_ALG_CTR:
         return "CTR";
      default:  // TPMI_ALG_SYM_MODE is not an enum
         return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<std::string> curve_id_tss2_to_botan(TPMI_ECC_CURVE mode_id) {
   // Currently, tpm2-tss does not include support for Brainpool curves or 25519/448.
   // Once the corresponding PR (https://github.com/tpm2-software/tpm2-tss/pull/2897) is merged and released,
   // this function should be updated.
   switch(mode_id) {
      case TPM2_ECC_NIST_P192:
         return "secp192r1";
      case TPM2_ECC_NIST_P224:
         return "secp224r1";
      case TPM2_ECC_NIST_P256:
         return "secp256r1";
      case TPM2_ECC_NIST_P384:
         return "secp384r1";
      case TPM2_ECC_NIST_P521:
         return "secp521r1";
      case TPM2_ECC_SM2_P256:
         return "sm2p256v1";
      default:
         return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<size_t> curve_id_order_byte_size(TPMI_ECC_CURVE curve_id) {
   switch(curve_id) {
      case TPM2_ECC_NIST_P192:
         return 24;
      case TPM2_ECC_NIST_P224:
         return 28;
      case TPM2_ECC_NIST_P256:
         return 32;
      case TPM2_ECC_NIST_P384:
         return 48;
      case TPM2_ECC_NIST_P521:
         return 66;  // Rounded up to the next full byte
      case TPM2_ECC_SM2_P256:
         return 32;
      default:
         return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<TPM2_ECC_CURVE> get_tpm2_curve_id(const OID& curve_oid) {
   // Currently, tpm2-tss does not include support for Brainpool curves or 25519/448.
   // Once the corresponding PR (https://github.com/tpm2-software/tpm2-tss/pull/2897) is merged and released,
   // this function should be updated.
   const std::string curve_name = curve_oid.to_formatted_string();
   if(curve_name == "secp192r1") {
      return TPM2_ECC_NIST_P192;
   } else if(curve_name == "secp224r1") {
      return TPM2_ECC_NIST_P224;
   } else if(curve_name == "secp256r1") {
      return TPM2_ECC_NIST_P256;
   } else if(curve_name == "secp384r1") {
      return TPM2_ECC_NIST_P384;
   } else if(curve_name == "secp521r1") {
      return TPM2_ECC_NIST_P521;
   } else if(curve_name == "sm2p256v1") {
      return TPM2_ECC_SM2_P256;
   } else {
      return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<TPMI_ALG_SYM_MODE> cipher_mode_botan_to_tss2(std::string_view mode_name) noexcept {
   if(mode_name == "CFB") {
      return TPM2_ALG_CFB;
   } else if(mode_name == "CBC") {
      return TPM2_ALG_CBC;
   } else if(mode_name == "ECB") {
      return TPM2_ALG_ECB;
   } else if(mode_name == "OFB") {
      return TPM2_ALG_OFB;
   } else if(mode_name == "CTR" || mode_name == "CTR-BE") {
      return TPM2_ALG_CTR;
   } else {
      return std::nullopt;
   }
}

/**
 * @returns a Botan cipher mode name string if the @p cipher_id, @p key_bits and
 *          @p mode_name are known, otherwise std::nullopt
 */
[[nodiscard]] inline std::optional<std::string> cipher_tss2_to_botan(TPMT_SYM_DEF cipher_def) noexcept {
   const auto cipher_name = block_cipher_tss2_to_botan(cipher_def.algorithm, cipher_def.keyBits.sym);
   if(!cipher_name) {
      return std::nullopt;
   }

   const auto mode_name = cipher_mode_tss2_to_botan(cipher_def.mode.sym);
   if(!mode_name) {
      return std::nullopt;
   }

   return Botan::fmt("{}({})", mode_name.value(), cipher_name.value());
}

[[nodiscard]] inline std::optional<TPMT_SYM_DEF> cipher_botan_to_tss2(std::string_view algo_name) {
   SCAN_Name spec(algo_name);
   if(spec.arg_count() == 0) {
      return std::nullopt;
   }

   const auto cipher = block_cipher_botan_to_tss2(spec.arg(0));
   const auto mode = cipher_mode_botan_to_tss2(spec.algo_name());

   if(!cipher || !mode) {
      return std::nullopt;
   }

   return TPMT_SYM_DEF{
      .algorithm = cipher->first,
      .keyBits = {.sym = cipher->second},
      .mode = {.sym = mode.value()},
   };
}

[[nodiscard]] inline TPMT_SYM_DEF get_tpm2_sym_cipher_spec(std::string_view algo_name) {
   if(auto cipher = cipher_botan_to_tss2(algo_name)) {
      return cipher.value();
   }

   throw Lookup_Error("TPM 2.0 Symmetric Cipher Spec", algo_name);
}

[[nodiscard]] inline std::optional<TPMI_ALG_SIG_SCHEME> rsa_signature_padding_botan_to_tss2(
   std::string_view padding_name) noexcept {
   // TODO(Botan4) remove the deprecated aliases
   if(padding_name == "EMSA_PKCS1" || padding_name == "PKCS1v15" || padding_name == "EMSA-PKCS1-v1_5" ||
      padding_name == "EMSA3") {
      return TPM2_ALG_RSASSA;
   } else if(padding_name == "PSS" || padding_name == "PSSR" || padding_name == "EMSA-PSS" ||
             padding_name == "PSS-MGF1" || padding_name == "EMSA4") {
      return TPM2_ALG_RSAPSS;
   } else {
      return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<TPMT_SIG_SCHEME> rsa_signature_scheme_botan_to_tss2(std::string_view name) {
   const SCAN_Name req(name);
   if(req.arg_count() == 0) {
      return std::nullopt;
   }

   const auto scheme = rsa_signature_padding_botan_to_tss2(req.algo_name());
   const auto hash = hash_algo_botan_to_tss2(req.arg(0));
   if(!scheme || !hash) {
      return std::nullopt;
   }

   if(scheme.value() == TPM2_ALG_RSAPSS && req.arg_count() != 1) {
      // RSA signing using PSS with MGF1
      return std::nullopt;
   }

   return TPMT_SIG_SCHEME{
      .scheme = scheme.value(),
      .details = {.any = {.hashAlg = hash.value()}},
   };
}

[[nodiscard]] inline std::optional<TPMI_ALG_ASYM_SCHEME> rsa_encryption_padding_botan_to_tss2(
   std::string_view name) noexcept {
   if(name == "OAEP" || name == "EME-OAEP" || name == "EME1") {
      return TPM2_ALG_OAEP;
   } else if(name == "PKCS1v15" || name == "EME-PKCS1-v1_5") {
      return TPM2_ALG_RSAES;
   } else if(name == "Raw") {
      return TPM2_ALG_NULL;
   } else {
      return std::nullopt;
   }
}

[[nodiscard]] inline std::optional<TPMT_RSA_DECRYPT> rsa_encryption_scheme_botan_to_tss2(std::string_view padding) {
   const SCAN_Name req(padding);
   const auto scheme = rsa_encryption_padding_botan_to_tss2(req.algo_name());
   if(!scheme) {
      return std::nullopt;
   }

   if(scheme.value() == TPM2_ALG_OAEP) {
      if(req.arg_count() < 1) {
         return std::nullopt;
      }

      const auto hash = hash_algo_botan_to_tss2(req.arg(0));
      if(!hash) {
         return std::nullopt;
      }

      return TPMT_RSA_DECRYPT{
         .scheme = scheme.value(),
         .details = {.oaep = {.hashAlg = hash.value()}},
      };
   } else if(scheme.value() == TPM2_ALG_RSAES) {
      return TPMT_RSA_DECRYPT{
         .scheme = scheme.value(),
         .details = {.rsaes = {}},
      };
   } else {
      return std::nullopt;
   }
}

}  // namespace Botan::TPM2

#endif
