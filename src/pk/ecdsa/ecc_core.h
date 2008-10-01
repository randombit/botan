/*************************************************
* ECC Core Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
* (C) 2007 FlexSecure GmbH                       *
*************************************************/

#ifndef BOTAN_ECC_CORE_H__
#define BOTAN_ECC_CORE_H__

#include <botan/bigint.h>
#include <botan/blinding.h>
#include <botan/pk_ops.h>

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ec_dompar.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_ECDSA)
/*************************************************
* ECDSA Core                                     *
*************************************************/
class ECDSA_Core
   {
   public:
      bool verify(const byte signature[], u32bit sig_len,
                  const byte message[], u32bit mess_len) const;

      SecureVector<byte> sign(const byte message[], u32bit mess_len) const;

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

/*************************************************
* ECKAEG Core                                    *
*************************************************/
class ECKAEG_Core
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
#endif

}

#endif
