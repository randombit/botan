/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves.h>

#include <botan/asn1_obj.h>

namespace Botan::PCurve {

//static
std::optional<PrimeOrderCurveId> PrimeOrderCurveId::from_string(std::string_view name) {
   if(name == "secp256r1") {
      return PCurve::PrimeOrderCurveId::secp256r1;
   } else if(name == "secp384r1") {
      return PCurve::PrimeOrderCurveId::secp384r1;
   } else if(name == "secp521r1") {
      return PCurve::PrimeOrderCurveId::secp521r1;
   } else if(name == "secp256k1") {
      return PCurve::PrimeOrderCurveId::secp256k1;
   } else {
      return {};
   }
}

//static
std::optional<PrimeOrderCurveId> PrimeOrderCurveId::from_oid(const OID& oid) {
   const std::string name = oid.human_name_or_empty();
   if(name.empty()) {
      return {};
   } else {
      return PrimeOrderCurveId::from_string(name);
   }
}

std::string PrimeOrderCurveId::to_string() const {
   switch(this->code()) {
      case PrimeOrderCurveId::secp256r1:
         return "secp256r1";
      case PrimeOrderCurveId::secp384r1:
         return "secp384r1";
      case PrimeOrderCurveId::secp521r1:
         return "secp521r1";
      case PrimeOrderCurveId::secp256k1:
         return "secp256k1";
   }

   return "unknown";
}

}  // namespace Botan::PCurve
