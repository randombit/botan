/*
* (C) 2019,2020,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_h2c.h>

#include <botan/ec_group.h>
#include <botan/internal/pcurves.h>

namespace Botan {

EC_Point hash_to_curve_sswu(const EC_Group& group,
                            std::string_view hash_fn,
                            std::span<const uint8_t> input,
                            std::span<const uint8_t> domain_sep,
                            bool random_oracle) {
   if(auto group_id = PCurve::PrimeOrderCurveId::from_oid(group.get_curve_oid())) {
      if(auto curve = PCurve::PrimeOrderCurve::from_id(*group_id)) {
         const auto pt = curve->hash_to_curve(hash_fn, input, domain_sep, random_oracle);
         return group.OS2ECP(pt.to_affine().serialize());
      }
   }

   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

}  // namespace Botan
