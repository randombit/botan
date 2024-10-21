/*
 * Classic McEliece Parameters
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce_parameter_set.h>

namespace Botan {

Classic_McEliece_Parameter_Set Classic_McEliece_Parameter_Set::from_string(std::string_view param_name) {
   Code code = [&] {
      if(param_name == "mceliece348864") {
         return mceliece348864;
      }
      if(param_name == "mceliece348864f") {
         return mceliece348864f;
      }
      if(param_name == "mceliece460896") {
         return mceliece460896;
      }
      if(param_name == "mceliece460896f") {
         return mceliece460896f;
      }
      if(param_name == "mceliece6688128") {
         return mceliece6688128;
      }
      if(param_name == "mceliece6688128f") {
         return mceliece6688128f;
      }
      if(param_name == "mceliece6688128pc") {
         return mceliece6688128pc;
      }
      if(param_name == "mceliece6688128pcf") {
         return mceliece6688128pcf;
      }
      if(param_name == "mceliece6960119") {
         return mceliece6960119;
      }
      if(param_name == "mceliece6960119f") {
         return mceliece6960119f;
      }
      if(param_name == "mceliece6960119pc") {
         return mceliece6960119pc;
      }
      if(param_name == "mceliece6960119pcf") {
         return mceliece6960119pcf;
      }
      if(param_name == "mceliece8192128") {
         return mceliece8192128;
      }
      if(param_name == "mceliece8192128f") {
         return mceliece8192128f;
      }
      if(param_name == "mceliece8192128pc") {
         return mceliece8192128pc;
      }
      if(param_name == "mceliece8192128pcf") {
         return mceliece8192128pcf;
      }

      throw Decoding_Error("Cannot convert string to CMCE parameter set");
   }();
   return Classic_McEliece_Parameter_Set(code);
}

std::string Classic_McEliece_Parameter_Set::to_string() const {
   switch(m_code) {
      case mceliece348864:
         return "mceliece348864";
      case mceliece348864f:
         return "mceliece348864f";
      case mceliece460896:
         return "mceliece460896";
      case mceliece460896f:
         return "mceliece460896f";
      case mceliece6688128:
         return "mceliece6688128";
      case mceliece6688128f:
         return "mceliece6688128f";
      case mceliece6688128pc:
         return "mceliece6688128pc";
      case mceliece6688128pcf:
         return "mceliece6688128pcf";
      case mceliece6960119:
         return "mceliece6960119";
      case mceliece6960119f:
         return "mceliece6960119f";
      case mceliece6960119pc:
         return "mceliece6960119pc";
      case mceliece6960119pcf:
         return "mceliece6960119pcf";
      case mceliece8192128:
         return "mceliece8192128";
      case mceliece8192128f:
         return "mceliece8192128f";
      case mceliece8192128pc:
         return "mceliece8192128pc";
      case mceliece8192128pcf:
         return "mceliece8192128pcf";
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Classic_McEliece_Parameter_Set Classic_McEliece_Parameter_Set::from_oid(const OID& oid) {
   return from_string(oid.to_formatted_string());
}

}  // namespace Botan
