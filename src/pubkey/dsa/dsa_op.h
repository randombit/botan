/*
* DSA Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DSA_OPS_H__
#define BOTAN_DSA_OPS_H__

#include <botan/numthry.h>
#include <botan/pow_mod.h>
#include <botan/reducer.h>
#include <botan/dl_group.h>

namespace Botan {

/*
* DSA Operation
*/
class BOTAN_DLL DSA_Operation
   {
   public:
      virtual bool verify(const byte[], u32bit,
                          const byte[], u32bit) const = 0;
      virtual SecureVector<byte> sign(const byte[], u32bit,
                                      const BigInt&) const = 0;
      virtual DSA_Operation* clone() const = 0;
      virtual ~DSA_Operation() {}
   };

/*
* Botan's Default DSA Operation
*/
class BOTAN_DLL Default_DSA_Op : public DSA_Operation
   {
   public:
      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      DSA_Operation* clone() const { return new Default_DSA_Op(*this); }

      Default_DSA_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt x, y;
      const DL_Group group;
      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Modular_Reducer mod_p, mod_q;
   };

}

#endif
