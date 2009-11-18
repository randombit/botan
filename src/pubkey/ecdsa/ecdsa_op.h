/*
* ECDSA Operations
* (C) 1999-2008 Jack Lloyd
* (C) 2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECDSA_OPERATIONS_H__
#define BOTAN_ECDSA_OPERATIONS_H__

#include <botan/ec_dompar.h>

namespace Botan {

/*
* ECDSA Operation
*/
class BOTAN_DLL ECDSA_Operation
   {
   public:
      virtual bool verify(const byte msg[], u32bit msg_len,
                          const byte sig[], u32bit sig_len) const = 0;

      virtual SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                                      const BigInt& k) const = 0;

      virtual ECDSA_Operation* clone() const = 0;

      virtual ~ECDSA_Operation() {}
   };

/*
* Default ECDSA operation
*/
class BOTAN_DLL Default_ECDSA_Op : public ECDSA_Operation
   {
   public:
      bool verify(const byte sig[], u32bit sig_len,
                  const byte msg[], u32bit msg_len) const;

      SecureVector<byte> sign(const byte msg[], u32bit msg_len,
                              const BigInt& k) const;

      ECDSA_Operation* clone() const
         {
         return new Default_ECDSA_Op(*this);
         }

      Default_ECDSA_Op(const EC_Domain_Params& dom_pars,
                       const BigInt& priv_key,
                       const PointGFp& pub_key);
   private:
      EC_Domain_Params dom_pars;
      PointGFp pub_key;
      BigInt priv_key;
   };

}

#endif
