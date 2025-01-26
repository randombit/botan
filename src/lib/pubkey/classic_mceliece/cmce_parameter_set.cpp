/*
 * Classic McEliece Parameters
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/cmce_parameter_set.h>

#include <botan/assert.h>
#include <botan/internal/fmt.h>

namespace Botan {

Classic_McEliece_Parameter_Set Classic_McEliece_Parameter_Set::from_string(std::string_view nm) {
   Code code = [&] {
      if(nm == "ClassicMcEliece_348864" || nm == "348864") {
         return ClassicMcEliece_348864;
      }
      if(nm == "ClassicMcEliece_348864f" || nm == "348864f") {
         return ClassicMcEliece_348864f;
      }
      if(nm == "ClassicMcEliece_460896" || nm == "460896") {
         return ClassicMcEliece_460896;
      }
      if(nm == "ClassicMcEliece_460896f" || nm == "460896f") {
         return ClassicMcEliece_460896f;
      }
      if(nm == "ClassicMcEliece_6688128" || nm == "6688128") {
         return ClassicMcEliece_6688128;
      }
      if(nm == "ClassicMcEliece_6688128f" || nm == "6688128f") {
         return ClassicMcEliece_6688128f;
      }
      if(nm == "ClassicMcEliece_6688128pc" || nm == "6688128pc") {
         return ClassicMcEliece_6688128pc;
      }
      if(nm == "ClassicMcEliece_6688128pcf" || nm == "6688128pcf") {
         return ClassicMcEliece_6688128pcf;
      }
      if(nm == "ClassicMcEliece_6960119" || nm == "6960119") {
         return ClassicMcEliece_6960119;
      }
      if(nm == "ClassicMcEliece_6960119f" || nm == "6960119f") {
         return ClassicMcEliece_6960119f;
      }
      if(nm == "ClassicMcEliece_6960119pc" || nm == "6960119pc") {
         return ClassicMcEliece_6960119pc;
      }
      if(nm == "ClassicMcEliece_6960119pcf" || nm == "6960119pcf") {
         return ClassicMcEliece_6960119pcf;
      }
      if(nm == "ClassicMcEliece_8192128" || nm == "8192128") {
         return ClassicMcEliece_8192128;
      }
      if(nm == "ClassicMcEliece_8192128f" || nm == "8192128f") {
         return ClassicMcEliece_8192128f;
      }
      if(nm == "ClassicMcEliece_8192128pc" || nm == "8192128pc") {
         return ClassicMcEliece_8192128pc;
      }
      if(nm == "ClassicMcEliece_8192128pcf" || nm == "8192128pcf") {
         return ClassicMcEliece_8192128pcf;
      }

      throw Invalid_Argument(fmt("Cannot convert '{}' to ClassicMcEliece parameter set", nm));
   }();
   return Classic_McEliece_Parameter_Set(code);
}

std::string Classic_McEliece_Parameter_Set::to_string() const {
   switch(m_code) {
      case ClassicMcEliece_348864:
         return "ClassicMcEliece_348864";
      case ClassicMcEliece_348864f:
         return "ClassicMcEliece_348864f";
      case ClassicMcEliece_460896:
         return "ClassicMcEliece_460896";
      case ClassicMcEliece_460896f:
         return "ClassicMcEliece_460896f";
      case ClassicMcEliece_6688128:
         return "ClassicMcEliece_6688128";
      case ClassicMcEliece_6688128f:
         return "ClassicMcEliece_6688128f";
      case ClassicMcEliece_6688128pc:
         return "ClassicMcEliece_6688128pc";
      case ClassicMcEliece_6688128pcf:
         return "ClassicMcEliece_6688128pcf";
      case ClassicMcEliece_6960119:
         return "ClassicMcEliece_6960119";
      case ClassicMcEliece_6960119f:
         return "ClassicMcEliece_6960119f";
      case ClassicMcEliece_6960119pc:
         return "ClassicMcEliece_6960119pc";
      case ClassicMcEliece_6960119pcf:
         return "ClassicMcEliece_6960119pcf";
      case ClassicMcEliece_8192128:
         return "ClassicMcEliece_8192128";
      case ClassicMcEliece_8192128f:
         return "ClassicMcEliece_8192128f";
      case ClassicMcEliece_8192128pc:
         return "ClassicMcEliece_8192128pc";
      case ClassicMcEliece_8192128pcf:
         return "ClassicMcEliece_8192128pcf";
   }
   BOTAN_ASSERT_UNREACHABLE();
}

Classic_McEliece_Parameter_Set Classic_McEliece_Parameter_Set::from_oid(const OID& oid) {
   return from_string(oid.to_formatted_string());
}

}  // namespace Botan
