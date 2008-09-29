/*************************************************
* Blinder Header File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BLINDER_H__
#define BOTAN_BLINDER_H__

#include <botan/bigint.h>
#include <botan/reducer.h>

namespace Botan {

/*************************************************
* Blinding Function Object                       *
*************************************************/
class BOTAN_DLL Blinder
   {
   public:
      BigInt blind(const BigInt&) const;
      BigInt unblind(const BigInt&) const;

      Blinder() {}
      Blinder(const BigInt&, const BigInt&, const BigInt&);
   private:
      Modular_Reducer reducer;
      mutable BigInt e, d;
   };

}

#endif
