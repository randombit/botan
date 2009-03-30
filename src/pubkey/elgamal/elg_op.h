/*
* ElGamal Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ELGAMAL_OPS_H__
#define BOTAN_ELGAMAL_OPS_H__

#include <botan/pow_mod.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/dl_group.h>

namespace Botan {

/*
* ElGamal Operation
*/
class BOTAN_DLL ELG_Operation
   {
   public:
      virtual SecureVector<byte> encrypt(const byte[], u32bit,
                                         const BigInt&) const = 0;
      virtual BigInt decrypt(const BigInt&, const BigInt&) const = 0;
      virtual ELG_Operation* clone() const = 0;
      virtual ~ELG_Operation() {}
   };

/*
* Botan's Default ElGamal Operation
*/
class BOTAN_DLL Default_ELG_Op : public ELG_Operation
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      BigInt decrypt(const BigInt&, const BigInt&) const;

      ELG_Operation* clone() const { return new Default_ELG_Op(*this); }

      Default_ELG_Op(const DL_Group&, const BigInt&, const BigInt&);
   private:
      const BigInt p;
      Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
      Fixed_Exponent_Power_Mod powermod_x_p;
      Modular_Reducer mod_p;
   };

}

#endif
