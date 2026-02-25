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
      };

      static MLDSA_Composite_Param get_param_by_id(MLDSA_Composite_Param::id_t id);
      static MLDSA_Composite_Param get_param_by_id_str(std::string_view id_str);

      size_t estimated_strength() const { throw Botan::Exception("not implemented"); }  // TODO

      OID object_identifier() const { return OID_Map::global_registry().str2oid(this->id_str); }

      // TODO: MAKE PRIVATE
      id_t id;
      const char* id_str;
      const char* label;
      const char* prehash_func;
      const char* mldsa_variant;
      const char* mldsa_oid_str;
      const char* traditional_algoritm;
      //const char*
      uint32_t mldsa_pubkey_size;
      uint32_t traditional_key_size;

   private:
};

}  // namespace Botan
#endif /* BOTAN_MLDSA_COMP_PARAMETERS_H_ */
