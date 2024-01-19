/*
 * Classic McEliece Parameters
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce_parameter_set.h>

namespace Botan {

Classic_McEliece_Parameter_Set cmce_param_set_from_str(std::string_view param_name) {
   if(param_name == "mceliece348864") {
      return Classic_McEliece_Parameter_Set::mceliece348864;
   }
   if(param_name == "mceliece348864f") {
      return Classic_McEliece_Parameter_Set::mceliece348864f;
   }
   if(param_name == "mceliece460896") {
      return Classic_McEliece_Parameter_Set::mceliece460896;
   }
   if(param_name == "mceliece460896f") {
      return Classic_McEliece_Parameter_Set::mceliece460896f;
   }
   if(param_name == "mceliece6688128") {
      return Classic_McEliece_Parameter_Set::mceliece6688128;
   }
   if(param_name == "mceliece6688128f") {
      return Classic_McEliece_Parameter_Set::mceliece6688128f;
   }
   if(param_name == "mceliece6688128pc") {
      return Classic_McEliece_Parameter_Set::mceliece6688128pc;
   }
   if(param_name == "mceliece6688128pcf") {
      return Classic_McEliece_Parameter_Set::mceliece6688128pcf;
   }
   if(param_name == "mceliece6960119") {
      return Classic_McEliece_Parameter_Set::mceliece6960119;
   }
   if(param_name == "mceliece6960119f") {
      return Classic_McEliece_Parameter_Set::mceliece6960119f;
   }
   if(param_name == "mceliece6960119pc") {
      return Classic_McEliece_Parameter_Set::mceliece6960119pc;
   }
   if(param_name == "mceliece6960119pcf") {
      return Classic_McEliece_Parameter_Set::mceliece6960119pcf;
   }
   if(param_name == "mceliece8192128") {
      return Classic_McEliece_Parameter_Set::mceliece8192128;
   }
   if(param_name == "mceliece8192128f") {
      return Classic_McEliece_Parameter_Set::mceliece8192128f;
   }
   if(param_name == "mceliece8192128pc") {
      return Classic_McEliece_Parameter_Set::mceliece8192128pc;
   }
   if(param_name == "mceliece8192128pcf") {
      return Classic_McEliece_Parameter_Set::mceliece8192128pcf;
   }

   throw Decoding_Error("Cannot convert string to CMCE parameter set");
}

std::string cmce_str_from_param_set(Classic_McEliece_Parameter_Set param) {
   switch(param) {
      case Classic_McEliece_Parameter_Set::mceliece348864:
         return "mceliece348864";
      case Classic_McEliece_Parameter_Set::mceliece348864f:
         return "mceliece348864f";
      case Classic_McEliece_Parameter_Set::mceliece460896:
         return "mceliece460896";
      case Classic_McEliece_Parameter_Set::mceliece460896f:
         return "mceliece460896f";
      case Classic_McEliece_Parameter_Set::mceliece6688128:
         return "mceliece6688128";
      case Classic_McEliece_Parameter_Set::mceliece6688128f:
         return "mceliece6688128f";
      case Classic_McEliece_Parameter_Set::mceliece6688128pc:
         return "mceliece6688128pc";
      case Classic_McEliece_Parameter_Set::mceliece6688128pcf:
         return "mceliece6688128pcf";
      case Classic_McEliece_Parameter_Set::mceliece6960119:
         return "mceliece6960119";
      case Classic_McEliece_Parameter_Set::mceliece6960119f:
         return "mceliece6960119f";
      case Classic_McEliece_Parameter_Set::mceliece6960119pc:
         return "mceliece6960119pc";
      case Classic_McEliece_Parameter_Set::mceliece6960119pcf:
         return "mceliece6960119pcf";
      case Classic_McEliece_Parameter_Set::mceliece8192128:
         return "mceliece8192128";
      case Classic_McEliece_Parameter_Set::mceliece8192128f:
         return "mceliece8192128f";
      case Classic_McEliece_Parameter_Set::mceliece8192128pc:
         return "mceliece8192128pc";
      case Classic_McEliece_Parameter_Set::mceliece8192128pcf:
         return "mceliece8192128pcf";
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Classic_McEliece_Parameter_Set cmce_param_set_from_oid(const OID& oid) {
   return cmce_param_set_from_str(oid.to_formatted_string());
}

}  // namespace Botan
