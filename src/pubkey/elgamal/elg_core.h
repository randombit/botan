/*
* ElGamal Core
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ELGAMAL_CORE_H__
#define BOTAN_ELGAMAL_CORE_H__

#include <botan/elg_op.h>
#include <botan/blinding.h>
#include <botan/dl_group.h>

namespace Botan {

/*
* ElGamal Core
*/
class BOTAN_DLL ELG_Core
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      SecureVector<byte> decrypt(const byte[], u32bit) const;

      ELG_Core& operator=(const ELG_Core&);

      ELG_Core() { op = 0; }
      ELG_Core(const ELG_Core&);

      ELG_Core(const DL_Group&, const BigInt&);
      ELG_Core(RandomNumberGenerator&, const DL_Group&,
               const BigInt&, const BigInt&);

      ~ELG_Core() { delete op; }
   private:
      ELG_Operation* op;
      Blinder blinder;
      u32bit p_bytes;
   };

}

#endif
