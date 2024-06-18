/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

// clang-format off
namespace secp256k1 {

class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
   "0",
   "7",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
   "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
   "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"> {
};

class Curve final : public EllipticCurve<Params> {};

}

// clang-format on

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp256k1() {
   return PrimeOrderCurveImpl<secp256k1::Curve>::instance();
}

}  // namespace Botan::PCurve
