/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLINDER_H__
#define BOTAN_BLINDER_H__

#include <botan/bigint.h>
#include <botan/reducer.h>

namespace Botan {

/**
* Blinding Function Object
*/
class BOTAN_DLL Blinder
   {
   public:
      BigInt blind(const BigInt& x) const;
      BigInt unblind(const BigInt& x) const;

      bool initialized() const { return reducer.initialized(); }

      Blinder() {}

      /**
      * Construct a blinder
      * @param mask the forward (blinding) mask
      * @param inverse_mask the inverse of mask (depends on algo)
      * @param modulus of the group operations are performed in
      */
      Blinder(const BigInt& mask,
              const BigInt& inverse_mask,
              const BigInt& modulus);

   private:
      Modular_Reducer reducer;
      mutable BigInt e, d;
   };

}

#endif
