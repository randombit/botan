/*
* ECKAEG Operations
* (C) 1999-2008 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECKAEG_OPERATIONS_H__
#define BOTAN_ECKAEG_OPERATIONS_H__

#include <botan/ec_dompar.h>

namespace Botan {

/*
* ECKAEG Operation
*/
class BOTAN_DLL ECKAEG_Operation
   {
   public:
      virtual SecureVector<byte> agree(const PointGFp&) const = 0;
      virtual ECKAEG_Operation* clone() const = 0;
      virtual ~ECKAEG_Operation() {}
   };

/*
* Default ECKAEG operation
*/
class BOTAN_DLL Default_ECKAEG_Op : public ECKAEG_Operation
   {
   public:
      SecureVector<byte> agree(const PointGFp& i) const;

      ECKAEG_Operation* clone() const { return new Default_ECKAEG_Op(*this); }

      Default_ECKAEG_Op(const EC_Domain_Params& dom_pars,
                        const BigInt& priv_key,
                        const PointGFp& pub_key);
   private:
      EC_Domain_Params m_dom_pars;
      PointGFp m_pub_key;
      BigInt m_priv_key;
   };


}

#endif
