/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_INSTANCE_H_
#define BOTAN_PCURVES_INSTANCE_H_

#include <memory>

namespace Botan::PCurve {

class PrimeOrderCurve;

class PCurveInstance final {
   public:
      /*
      * All functions here are always defined, however if the cooresponding
      * curve is not available at build time a default implementation is
      * provided in pcurves_instance.cpp that returns a nullptr
      */

      static std::shared_ptr<const PrimeOrderCurve> secp192r1();

      static std::shared_ptr<const PrimeOrderCurve> secp224r1();

      static std::shared_ptr<const PrimeOrderCurve> secp256r1();

      static std::shared_ptr<const PrimeOrderCurve> secp384r1();

      static std::shared_ptr<const PrimeOrderCurve> secp521r1();

      static std::shared_ptr<const PrimeOrderCurve> secp256k1();

      static std::shared_ptr<const PrimeOrderCurve> brainpool256r1();

      static std::shared_ptr<const PrimeOrderCurve> brainpool384r1();

      static std::shared_ptr<const PrimeOrderCurve> brainpool512r1();

      static std::shared_ptr<const PrimeOrderCurve> frp256v1();

      static std::shared_ptr<const PrimeOrderCurve> sm2p256v1();

      static std::shared_ptr<const PrimeOrderCurve> numsp512d1();
};

}  // namespace Botan::PCurve

#endif
