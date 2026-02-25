
#include "botan/exceptn.h"
#include <botan/asn1_obj.h>
#include <botan/mldsa_comp_parameters.h>
#include <botan/oids.h>
#include <botan/pss_params.h>
#include <string_view>

namespace Botan {

static const std::array<MLDSA_Composite_Param, 1> mldsa_composite_registry = {{
   {MLDSA_Composite_Param::id_t::id_MLDSA44_RSA2048_PSS_SHA256,
    "id-MLDSA44-RSA2048-PSS-SHA256",
    "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
    "SHA256",
    "ML-DSA-4x4",
    "2.16.840.1.101.3.4.3.17",  // ML-DSA OID
    "RSA/PSS(SHA-256,MGF1,32)",
    1312,
    2048},
}};

// static
MLDSA_Composite_Param MLDSA_Composite_Param::get_param_by_id_str(std::string_view id_str) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.id_str == id_str) {
         return param;
      }
   }
   throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite id (string)");
}

// static
MLDSA_Composite_Param MLDSA_Composite_Param::get_param_by_id(MLDSA_Composite_Param::id_t id) {
   for(const auto& param : mldsa_composite_registry) {
      if(param.id == id) {
         return param;
      }
   }
   throw Botan::Invalid_Argument("no parameter found for provided MLDSA composite id (enum)");
}

}  // namespace Botan
