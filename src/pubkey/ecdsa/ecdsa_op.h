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
#include <botan/rng.h>

namespace Botan {

/*
* ECDSA Operation
*/
class BOTAN_DLL ECDSA_Operation
   {
   public:
      virtual bool verify(const byte sig[], u32bit sig_len,
                          const byte msg[], u32bit msg_len) const = 0;

      virtual SecureVector<byte> sign(const byte message[],
                                      u32bit mess_len,
                                      RandomNumberGenerator&) const = 0;

      virtual ECDSA_Operation* clone() const = 0;

      virtual ~ECDSA_Operation() {}
   };


/*
* Default ECDSA operation
*/
class BOTAN_DLL Default_ECDSA_Op : public ECDSA_Operation
   {
   public:
      bool verify(const byte signature[], u32bit sig_len,
                  const byte message[], u32bit mess_len) const;

      SecureVector<byte> sign(const byte message[], u32bit mess_len,
                              RandomNumberGenerator& rng) const;

      ECDSA_Operation* clone() const
         {
         return new Default_ECDSA_Op(*this);
         }

      Default_ECDSA_Op(const EC_Domain_Params& dom_pars,
                       const BigInt& priv_key,
                       const PointGFp& pub_key);
   private:
      EC_Domain_Params m_dom_pars;
      PointGFp m_pub_key;
      BigInt m_priv_key;
   };

}

#endif
