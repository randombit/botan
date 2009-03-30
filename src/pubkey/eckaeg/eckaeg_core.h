/*
* ECKAEG Core
* (C) 1999-2007 Jack Lloyd
* (C) 2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECKAEG_CORE_H__
#define BOTAN_ECKAEG_CORE_H__

#include <botan/eckaeg_op.h>
#include <botan/blinding.h>
#include <botan/ec_dompar.h>

namespace Botan {

/*
* ECKAEG Core
*/
class BOTAN_DLL ECKAEG_Core
   {
   public:
      SecureVector<byte> agree(const PointGFp&) const;

      ECKAEG_Core& operator=(const ECKAEG_Core&);

      ECKAEG_Core() { op = 0; }

      ECKAEG_Core(const ECKAEG_Core&);

      ECKAEG_Core(const EC_Domain_Params& dom_pars,
                  const BigInt& priv_key,
                  PointGFp const& pub_key);

      ~ECKAEG_Core() { delete op; }
   private:
      ECKAEG_Operation* op;
      Blinder blinder;
   };

}

#endif
