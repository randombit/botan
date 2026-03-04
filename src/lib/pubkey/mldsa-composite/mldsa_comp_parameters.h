/*
 * ML-DSA Composite Signature Schemes 
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLDSA_COMP_PARAMETERS_H_
#define BOTAN_MLDSA_COMP_PARAMETERS_H_

#include <botan/exceptn.h>
#include <botan/types.h>
#include <botan/internal/oid_map.h>

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) MLDSA_Composite_Param {
   public:
      enum id_t : uint32_t /* NOLINT(*-enum-size,*-use-enum-class) */ {
         id_MLDSA44_RSA2048_PSS_SHA256,
         id_MLDSA44_RSA2048_PKCS15_SHA256,
      };

      static MLDSA_Composite_Param get_param_by_id(MLDSA_Composite_Param::id_t id);
      static MLDSA_Composite_Param get_param_by_id_str(std::string_view id_str);

      MLDSA_Composite_Param clone() const { return MLDSA_Composite_Param::get_param_by_id(id); }

      size_t estimated_strength() const { throw Botan::Exception("not implemented"); }  // TODO

      AlgorithmIdentifier get_mldsa_algorithm_id() const;
      AlgorithmIdentifier get_traditional_algorithm_id() const;

      OID object_identifier() const { return OID_Map::global_registry().str2oid(this->id_str); }

      std::string mldsa_param_str() const;

      size_t mldsa_signature_size() const;
      size_t traditional_signature_size() const;

      size_t signature_size() const { return mldsa_signature_size() + traditional_signature_size(); }

      size_t traditional_pubkey_encoded_size() const;

      size_t mldsa_privkey_size() const { return 32; }

      // TODO: MAKE PRIVATE
      id_t id;
      const std::string id_str;
      const std::string label;
      const std::string prehash_func;
      const std::string mldsa_variant;
      const std::string mldsa_oid_str;
      const std::string traditional_algoritm;
      const std::string traditional_padding;
      uint32_t mldsa_pubkey_size;
      uint32_t traditional_key_size;

      //MLDSA_Composite_Param() = delete;

   private:
};

}  // namespace Botan
#endif /* BOTAN_MLDSA_COMP_PARAMETERS_H_ */
