/*************************************************
* Blinder Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BLINDER_H__
#define BOTAN_BLINDER_H__

#include <botan/bigint.h>
#include <botan/bigint/reducer.h>


namespace Botan {

/*************************************************
* Blinding Function Object                       *
*************************************************/
class Blinder
   {
   public:
      /**
       * blind a BigInt
       * @param i the BigInt to blind
       * @result a blinded BigInt
       */
	   BigInt blind(const BigInt& i) const;

      /**
       * unblind a BigInt
       * @param i the BigInt to unblind
       * @result the unblinded BigInt
       */
      BigInt unblind(const BigInt& i) const;

      Blinder() {}

      /**
       * Blinder constructur
       * @param e
       * @param d
       * @param n
       */
      Blinder(const BigInt& e, const BigInt& d, const BigInt& n);
   private:
      Modular_Reducer reducer;
      mutable BigInt e, d;
   };

}

#endif
