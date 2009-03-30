/*
* DH Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DH_OPS_H__
#define BOTAN_DH_OPS_H__

#include <botan/dl_group.h>
#include <botan/reducer.h>
#include <botan/pow_mod.h>

namespace Botan {

/*
* DH Operation Interface
*/
class BOTAN_DLL DH_Operation
   {
   public:
      virtual BigInt agree(const BigInt&) const = 0;
      virtual DH_Operation* clone() const = 0;
      virtual ~DH_Operation() {}
   };

/*
* Botan's Default DH Operation
*/
class BOTAN_DLL Default_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const { return powermod_x_p(i); }
      DH_Operation* clone() const { return new Default_DH_Op(*this); }

      Default_DH_Op(const DL_Group& group, const BigInt& x) :
         powermod_x_p(x, group.get_p()) {}
   private:
      Fixed_Exponent_Power_Mod powermod_x_p;
   };

}

#endif
