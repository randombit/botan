/*
* NR Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_NR_OPS_H__
#define BOTAN_NR_OPS_H__

#include <botan/pow_mod.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/dl_group.h>

namespace Botan {

/*
* NR Operation
*/
class BOTAN_DLL NR_Operation
   {
   public:
      virtual SecureVector<byte> verify(const byte[], u32bit) const = 0;
      virtual SecureVector<byte> sign(const byte[], u32bit,
                                      const BigInt&) const = 0;
      virtual NR_Operation* clone() const = 0;
      virtual ~NR_Operation() {}
   };

/*
* Botan's Default NR Operation
*/
class BOTAN_DLL Default_NR_Op : public NR_Operation
   {
   public:
      SecureVector<byte> verify(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      NR_Operation* clone() const { return new Default_NR_Op(*this); }

      Default_NR_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Modular_Reducer mod_p, mod_q;
   };


}

#endif
