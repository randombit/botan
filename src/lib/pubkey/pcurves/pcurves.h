/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_H_
#define BOTAN_PCURVES_H_

#include <botan/types.h>
#include <span>
#include <string_view>
#include <vector>

namespace Botan::PCurve {

/// Identifier for a named prime order curve
enum class PrimeOrderCurveId {
   /// P-256 aka secp256r1
   P256,
   /// P-384 aka secp384r1
   P384,
   /// P-521 aka secp521r1
   P521,
};

std::vector<uint8_t> hash_to_curve(PrimeOrderCurveId curve,
                                   std::string_view hash,
                                   bool random_oracle,
                                   std::span<const uint8_t> input,
                                   std::span<const uint8_t> domain_sep);

}  // namespace Botan::PCurve

#endif
