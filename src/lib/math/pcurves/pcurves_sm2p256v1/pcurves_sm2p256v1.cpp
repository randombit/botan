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
namespace sm2p256v1 {

class Params final : public EllipticCurveParameters<
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
  "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
  "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
  "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
  "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"> {
};

class Curve final : public EllipticCurve<Params> {};

}

// clang-format on

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::sm2p256v1() {
   return PrimeOrderCurveImpl<sm2p256v1::Curve>::instance();
}

}  // namespace Botan::PCurve
