/*
* (C) 2019,2020,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_h2c.h>

#include <botan/ec_group.h>
#include <botan/internal/pcurves.h>

namespace Botan {

namespace {

PCurve::PrimeOrderCurveId group_id(const EC_Group& group) {
   const OID& oid = group.get_curve_oid();

   if(oid == OID{1, 2, 840, 10045, 3, 1, 7}) {  // secp256r1
      return PCurve::PrimeOrderCurveId::P256;
   }
   if(oid == OID{1, 3, 132, 0, 34}) {  // secp384r1
      return PCurve::PrimeOrderCurveId::P384;
   }
   if(oid == OID{1, 3, 132, 0, 35}) {  // secp521r1
      return PCurve::PrimeOrderCurveId::P521;
   }

   throw Invalid_Argument("hash_to_curve_sswu does not support this curve");
}

}  // namespace

EC_Point hash_to_curve_sswu(const EC_Group& group,
                            std::string_view hash_fn,
                            std::span<const uint8_t> input,
                            std::span<const uint8_t> domain_sep,
                            bool random_oracle) {
   const auto pt = PCurve::hash_to_curve(group_id(group), hash_fn, random_oracle, input, domain_sep);

   return group.OS2ECP(pt);
}

}  // namespace Botan
