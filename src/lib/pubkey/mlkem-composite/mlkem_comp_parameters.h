/*
 * ML-KEM Composite KEM Parameters
 * (C) 2026 Falko Strenzke, MTG AG
 *     2026 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLKEM_COMP_PARAMETERS_H_
#define BOTAN_MLKEM_COMP_PARAMETERS_H_

#include <botan/asn1_obj.h>

#include <optional>
#include <string_view>
#include <vector>

namespace Botan {

class BOTAN_PUBLIC_API(3, 13) MLKEM_Composite_Param {
   public:
      enum id_t : uint32_t /* NOLINT(*-enum-size,*-use-enum-class) */ {
         MLKEM768_RSA2048_SHA3_256,
         MLKEM768_RSA3072_SHA3_256,
         MLKEM768_RSA4096_SHA3_256,
         MLKEM768_X25519_SHA3_256,
         MLKEM768_ECDH_P256_SHA3_256,
         MLKEM768_ECDH_P384_SHA3_256,
         MLKEM1024_RSA3072_SHA3_256,
         MLKEM768_ECDH_brainpoolP256r1_SHA3_256,
         MLKEM1024_ECDH_P384_SHA3_256,
         MLKEM1024_ECDH_brainpoolP384r1_SHA3_256,
         MLKEM1024_X448_SHA3_256,
         MLKEM1024_ECDH_P521_SHA3_256
      };

      static inline const char* generic_algo_name = "ML-KEM-Composite";

      static std::vector<MLKEM_Composite_Param> all_param_sets();

      static std::vector<MLKEM_Composite_Param> all_supported_param_sets();

      /**
       * @brief Create a parameters object from the provided id. If the parameters are not supported by the build configuration of the library, throw a Not_Implemented exception.
       *
       * @param id The id of the parameter set to create.
       *
       * @return The parameter object.
       */
      static MLKEM_Composite_Param from_id_supported_or_throw(MLKEM_Composite_Param::id_t id);

      static std::optional<MLKEM_Composite_Param> from_id(MLKEM_Composite_Param::id_t id);

      static MLKEM_Composite_Param from_id_str_or_throw(std::string_view id_str);

      static std::optional<MLKEM_Composite_Param> from_id_str(std::string_view id_str);

      static std::optional<MLKEM_Composite_Param> from_algo_id(const AlgorithmIdentifier& algo_id);

      static MLKEM_Composite_Param from_algo_id_or_throw(const AlgorithmIdentifier& algo_id);

      /**
       * @brief
       * Find out whether the library build supports this parameter.
       *
       * @return true if the parameter is supported, false otherwise
       */
      bool is_supported() const;

      AlgorithmIdentifier get_composite_algorithm_id() const;

      AlgorithmIdentifier get_mlkem_algorithm_id() const;

      AlgorithmIdentifier get_traditional_algorithm_id() const;

      OID object_identifier() const;

      /* std::string mlkem_param_str() const; */

      std::string get_mlkem_mode() const { return std::string(m_mlkem_variant); }

      size_t mlkem_pubkey_size() const;

      MLKEM_Composite_Param::id_t id() const { return m_id; }

      std::string id_str() const { return std::string(this->m_id_str); }

      std::string label() const { return std::string(this->m_label); }

      std::string traditional_algorithm() const { return std::string(this->m_traditional_algorithm); }

      std::string traditional_padding() const { return std::string(this->m_traditional_padding); }

      std::string curve() const { return std::string(this->m_curve); }

      std::string get_traditional_algo_param_str() const;

      size_t mlkem_privkey_size() const { return 64; }

   private:
      MLKEM_Composite_Param(id_t id,
                            std::string_view id_str,
                            std::string_view label,
                            std::string_view mlkem_variant,
                            std::string_view traditional_algorithm,
                            std::string_view traditional_padding,
                            std::string_view curve,
                            uint32_t traditional_key_size) noexcept;

      std::string_view m_id_str;
      std::string_view m_label;
      std::string_view m_mlkem_variant;
      std::string_view m_traditional_algorithm;
      std::string_view m_traditional_padding;
      std::string_view m_curve;
      id_t m_id;
      uint32_t m_traditional_key_size;

      static const MLKEM_Composite_Param mlkem_composite_registry[];
};

}  // namespace Botan

#endif /* BOTAN_MLKEM_COMP_PARAMETERS_H_ */
