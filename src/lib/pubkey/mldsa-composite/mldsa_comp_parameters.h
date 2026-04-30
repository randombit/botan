/*
 * ML-DSA Composite Signature Schemes
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLDSA_COMP_PARAMETERS_H_
#define BOTAN_MLDSA_COMP_PARAMETERS_H_

#include <botan/dilithium.h>
#include <botan/exceptn.h>
#include <botan/types.h>
#include <botan/internal/oid_map.h>

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) MLDSA_Composite_Param {
   public:
      enum id_t : uint32_t /* NOLINT(*-enum-size,*-use-enum-class) */ {
#if defined(BOTAN_HAS_RSA)
         MLDSA44_RSA2048_PKCS15_SHA256,
         MLDSA65_RSA3072_PKCS15_SHA512,
         MLDSA65_RSA4096_PKCS15_SHA512,
#endif
#if defined(BOTAN_HAS_PSS)
         MLDSA44_RSA2048_PSS_SHA256,
         MLDSA65_RSA3072_PSS_SHA512,
         MLDSA65_RSA4096_PSS_SHA512,
         MLDSA87_RSA3072_PSS_SHA512,
         MLDSA87_RSA4096_PSS_SHA512,
#endif
#if defined(BOTAN_HAS_ECDSA)
         MLDSA44_ECDSA_P256_SHA256,
         MLDSA65_ECDSA_P256_SHA512,
         MLDSA65_ECDSA_P384_SHA512,
         MLDSA65_ECDSA_brainpoolP256r1_SHA512,
         MLDSA87_ECDSA_P384_SHA512,
         MLDSA87_ECDSA_brainpoolP384r1_SHA512,
         MLDSA87_ECDSA_P521_SHA512,
#endif
#if defined(BOTAN_HAS_ED25519)
         MLDSA44_Ed25519_SHA512,
         MLDSA65_Ed25519_SHA512,
#endif
#if defined(BOTAN_HAS_ED448)
         MLDSA87_Ed448_SHAKE256,
#endif
      };

      static std::vector<MLDSA_Composite_Param> all_param_sets();

      static MLDSA_Composite_Param from_id_or_throw(MLDSA_Composite_Param::id_t id);

      static std::optional<MLDSA_Composite_Param> from_id(MLDSA_Composite_Param::id_t id);

      static MLDSA_Composite_Param from_id_str_or_throw(std::string_view id_str);

      static std::optional<MLDSA_Composite_Param> from_id_str(std::string_view id_str);

      static std::optional<MLDSA_Composite_Param> from_algo_id(const AlgorithmIdentifier& algo_id);

      static MLDSA_Composite_Param from_algo_id_or_throw(const AlgorithmIdentifier& algo_id);

      MLDSA_Composite_Param clone() const { return MLDSA_Composite_Param::from_id_or_throw(m_id); }

      AlgorithmIdentifier get_composite_algorithm_id() const;

      AlgorithmIdentifier get_mldsa_algorithm_id() const;

      AlgorithmIdentifier get_traditional_algorithm_id() const;

      OID object_identifier() const { return OID_Map::global_registry().str2oid(this->m_id_str); }

      std::string mldsa_param_str() const;

      DilithiumMode get_mldsa_mode() const { return m_mldsa_variant; }

      size_t mldsa_signature_size() const;

      size_t mldsa_pubkey_size() const;

      const char* mldsa_oid_str() const;

      MLDSA_Composite_Param::id_t id() const { return m_id; }

      std::string id_str() const { return std::string(this->m_id_str); }

      std::string label() const { return std::string(this->m_label); }

      std::string prehash_func() const { return std::string(this->m_prehash_func); }

      std::string traditional_algorithm() const { return std::string(this->m_traditional_algorithm); }

      std::string traditional_padding() const { return std::string(this->m_traditional_padding); }

      std::string curve() const { return std::string(this->m_curve); }

      std::string get_traditional_algo_param_str() const;
      size_t traditional_pubkey_encoded_size() const;

      size_t mldsa_privkey_size() const { return 32; }

      MLDSA_Composite_Param(id_t id,
                            const char* id_str,
                            const char* label,
                            const char* prehash_func,
                            DilithiumMode::Mode mldsa_variant,
                            const char* traditional_algorithm,
                            const char* traditional_padding,
                            const char* curve,
                            uint32_t traditional_key_size) noexcept;

   private:
      // m_id_str, m_label, m_prehash_func, m_traditional_algorithm, m_traditional_padding, m_curve, m_id, m_traditional_key_size, m_mldsa_variant,
      const char* m_id_str;
      const char* m_label;
      const char* m_prehash_func;
      const char* m_traditional_algorithm;
      const char* m_traditional_padding;
      const char* m_curve;
      id_t m_id;
      uint32_t m_traditional_key_size;
      DilithiumMode::Mode m_mldsa_variant;

      static const MLDSA_Composite_Param mldsa_composite_registry[];
};

}  // namespace Botan
#endif /* BOTAN_MLDSA_COMP_PARAMETERS_H_ */
