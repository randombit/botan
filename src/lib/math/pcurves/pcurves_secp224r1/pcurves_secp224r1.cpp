/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace secp224r1 {

// TODO Secp224r1Rep

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
   "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
   "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
   "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"> {
};

// clang-format on

class Curve final : public EllipticCurve<Params> {};

}  // namespace secp224r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp224r1() {
   return PrimeOrderCurveImpl<secp224r1::Curve>::instance();
}

}  // namespace Botan::PCurve
