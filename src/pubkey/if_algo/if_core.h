/*
* IF Algorithm Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_IF_CORE_H__
#define BOTAN_IF_CORE_H__

#include <botan/if_op.h>
#include <botan/blinding.h>

namespace Botan {

/*
* IF Core
*/
class BOTAN_DLL IF_Core
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Core& operator=(const IF_Core&);

      IF_Core() { op = 0; }
      IF_Core(const IF_Core&);

      IF_Core(const BigInt&, const BigInt&);

      IF_Core(RandomNumberGenerator& rng,
              const BigInt&, const BigInt&,
              const BigInt&, const BigInt&, const BigInt&,
              const BigInt&, const BigInt&, const BigInt&);

      ~IF_Core() { delete op; }
   private:
      IF_Operation* op;
      Blinder blinder;
   };

}

#endif
