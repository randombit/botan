/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves.h>

#include <botan/internal/pcurves_instance.h>

#if defined(BOTAN_HAS_ASN1)
   #include <botan/asn1_obj.h>
#endif

namespace Botan::PCurve {

#if !defined(BOTAN_HAS_PCURVES_SECP256R1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256r1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_SECP384R1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp384r1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_SECP521R1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp521r1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_SECP256K1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256k1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_BRAINPOOL256R1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::brainpool256r1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_BRAINPOOL384R1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::brainpool384r1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_BRAINPOOL512R1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::brainpool512r1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_FRP256V1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::frp256v1() {
   return nullptr;
}
#endif

#if !defined(BOTAN_HAS_PCURVES_SM2P256V1)
//static
std::shared_ptr<const PrimeOrderCurve> PCurveInstance::sm2p256v1() {
   return nullptr;
}
#endif

std::shared_ptr<const PrimeOrderCurve> PrimeOrderCurve::from_id(PrimeOrderCurveId id) {
   switch(id.code()) {
      case PrimeOrderCurveId::secp256r1:
         return PCurveInstance::secp256r1();
      case PrimeOrderCurveId::secp384r1:
         return PCurveInstance::secp384r1();
      case PrimeOrderCurveId::secp521r1:
         return PCurveInstance::secp521r1();
      case PrimeOrderCurveId::secp256k1:
         return PCurveInstance::secp256k1();
      case PrimeOrderCurveId::brainpool256r1:
         return PCurveInstance::brainpool256r1();
      case PrimeOrderCurveId::brainpool384r1:
         return PCurveInstance::brainpool384r1();
      case PrimeOrderCurveId::brainpool512r1:
         return PCurveInstance::brainpool512r1();
      case PrimeOrderCurveId::frp256v1:
         return PCurveInstance::frp256v1();
      case PrimeOrderCurveId::sm2p256v1:
         return PCurveInstance::sm2p256v1();
   }
   return {};
}

std::vector<PrimeOrderCurveId> PrimeOrderCurveId::all() {
   return {
      PrimeOrderCurveId::secp256r1,
      PrimeOrderCurveId::secp384r1,
      PrimeOrderCurveId::secp521r1,
      PrimeOrderCurveId::secp256k1,
      PrimeOrderCurveId::brainpool256r1,
      PrimeOrderCurveId::brainpool384r1,
      PrimeOrderCurveId::brainpool512r1,
      PrimeOrderCurveId::frp256v1,
      PrimeOrderCurveId::sm2p256v1,
   };
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
      case PrimeOrderCurveId::brainpool256r1:
         return "brainpool256r1";
      case PrimeOrderCurveId::brainpool384r1:
         return "brainpool384r1";
      case PrimeOrderCurveId::brainpool512r1:
         return "brainpool512r1";
      case PrimeOrderCurveId::frp256v1:
         return "frp256v1";
      case PrimeOrderCurveId::sm2p256v1:
         return "sm2p256v1";
   }

   return "unknown";
}

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
   } else if(name == "brainpool256r1") {
      return PCurve::PrimeOrderCurveId::brainpool256r1;
   } else if(name == "brainpool384r1") {
      return PCurve::PrimeOrderCurveId::brainpool384r1;
   } else if(name == "brainpool512r1") {
      return PCurve::PrimeOrderCurveId::brainpool512r1;
   } else if(name == "frp256v1") {
      return PCurve::PrimeOrderCurveId::frp256v1;
   } else if(name == "sm2p256v1") {
      return PCurve::PrimeOrderCurveId::sm2p256v1;
   } else {
      return {};
   }
}

#if defined(BOTAN_HAS_ASN1)

//static
std::optional<PrimeOrderCurveId> PrimeOrderCurveId::from_oid(const OID& oid) {
   const std::string name = oid.human_name_or_empty();
   if(name.empty()) {
      return {};
   } else {
      return PrimeOrderCurveId::from_string(name);
   }
}

#endif

}  // namespace Botan::PCurve
