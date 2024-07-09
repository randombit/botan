/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace secp192r1 {

// clang-format off
class Params final : public EllipticCurveParameters<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
   "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
   "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
   "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
   "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"> {
};

// clang-format on

class Curve final : public EllipticCurve<Params> {};

}  // namespace secp192r1

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::secp192r1() {
   return PrimeOrderCurveImpl<secp192r1::Curve>::instance();
}

}  // namespace Botan::PCurve
