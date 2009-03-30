/*
* IF Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_IF_OP_H__
#define BOTAN_IF_OP_H__

#include <botan/bigint.h>
#include <botan/pow_mod.h>
#include <botan/reducer.h>

namespace Botan {

/*
* IF Operation
*/
class BOTAN_DLL IF_Operation
   {
   public:
      virtual BigInt public_op(const BigInt&) const = 0;
      virtual BigInt private_op(const BigInt&) const = 0;
      virtual IF_Operation* clone() const = 0;
      virtual ~IF_Operation() {}
   };

/*
* Default IF Operation
*/
class BOTAN_DLL Default_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt& i) const
         { return powermod_e_n(i); }
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new Default_IF_Op(*this); }

      Default_IF_Op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);
   private:
      Fixed_Exponent_Power_Mod powermod_e_n, powermod_d1_p, powermod_d2_q;
      Modular_Reducer reducer;
      BigInt c, q;
   };

}

#endif
