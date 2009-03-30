/*
* ECDSA Core
* (C) 1999-2007 Jack Lloyd
* (C) 2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECDSA_CORE_H__
#define BOTAN_ECDSA_CORE_H__

#include <botan/ecdsa_op.h>
#include <botan/blinding.h>
#include <botan/ec_dompar.h>

namespace Botan {

/*
* ECDSA Core
*/
class BOTAN_DLL ECDSA_Core
   {
   public:
      bool verify(const byte signature[], u32bit sig_len,
                  const byte message[], u32bit mess_len) const;

      SecureVector<byte> sign(const byte message[], u32bit mess_len,
                              RandomNumberGenerator& rng) const;

      ECDSA_Core& operator=(const ECDSA_Core&);

      ECDSA_Core() { op = 0; }

      ECDSA_Core(const ECDSA_Core&);

      ECDSA_Core(const EC_Domain_Params& dom_pars,
                 const BigInt& priv_key,
                 const PointGFp& pub_key);

      ~ECDSA_Core() { delete op; }
   private:
      ECDSA_Operation* op;
   };

}

#endif
