/*
* ECKAEG implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eckaeg.h>
#include <botan/numthry.h>
#include <botan/util.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>

namespace Botan {

/*********************************
* ECKAEG_PublicKey
*********************************/

void ECKAEG_PublicKey::affirm_init() const // virtual
   {
   EC_PublicKey::affirm_init();
   }

void ECKAEG_PublicKey::set_all_values(ECKAEG_PublicKey const& other)
   {
   m_param_enc = other.m_param_enc;
   m_eckaeg_core = other.m_eckaeg_core;
   m_enc_public_point = other.m_enc_public_point;
   if(other.mp_dom_pars.get())
      {
      mp_dom_pars.reset(new EC_Domain_Params(*(other.mp_dom_pars)));
      }
   if(other.mp_public_point.get())
      {
      mp_public_point.reset(new PointGFp(*(other.mp_public_point)));
      }
   }

ECKAEG_PublicKey::ECKAEG_PublicKey(ECKAEG_PublicKey const& other)
   : Public_Key(),
     EC_PublicKey()
   {
   set_all_values(other);
   }

ECKAEG_PublicKey const& ECKAEG_PublicKey::operator=(ECKAEG_PublicKey const& rhs)
   {
   set_all_values(rhs);
   return *this;
   }

void ECKAEG_PublicKey::X509_load_hook()
   {
   EC_PublicKey::X509_load_hook();
   EC_PublicKey::affirm_init();
   m_eckaeg_core = ECKAEG_Core(*mp_dom_pars, BigInt(0), *mp_public_point);
   }

ECKAEG_PublicKey::ECKAEG_PublicKey(EC_Domain_Params const& dom_par, PointGFp const& public_point)
   {
   mp_dom_pars = std::auto_ptr<EC_Domain_Params>(new EC_Domain_Params(dom_par));
   mp_public_point = std::auto_ptr<PointGFp>(new PointGFp(public_point));
   if(mp_public_point->get_curve() != mp_dom_pars->get_curve())
      {
      throw Invalid_Argument("ECKAEG_PublicKey(): curve of arg. point and curve of arg. domain parameters are different");
      }
   EC_PublicKey::affirm_init();
   m_eckaeg_core = ECKAEG_Core(*mp_dom_pars, BigInt(0), *mp_public_point);
   }

/*********************************
* ECKAEG_PrivateKey
*********************************/
void ECKAEG_PrivateKey::affirm_init() const // virtual
   {
   EC_PrivateKey::affirm_init();
   }

void ECKAEG_PrivateKey::PKCS8_load_hook(bool generated)
   {
   EC_PrivateKey::PKCS8_load_hook(generated);
   EC_PrivateKey::affirm_init();
   m_eckaeg_core = ECKAEG_Core(*mp_dom_pars, m_private_value, *mp_public_point);
   }

void ECKAEG_PrivateKey::set_all_values(ECKAEG_PrivateKey const& other)
   {
   m_private_value = other.m_private_value;
   m_param_enc = other.m_param_enc;
   m_eckaeg_core = other.m_eckaeg_core;
   m_enc_public_point = other.m_enc_public_point;
   if(other.mp_dom_pars.get())
      {
      mp_dom_pars.reset(new EC_Domain_Params(*(other.mp_dom_pars)));
      }
   if(other.mp_public_point.get())
      {
      mp_public_point.reset(new PointGFp(*(other.mp_public_point)));
      }
   }

ECKAEG_PrivateKey::ECKAEG_PrivateKey(ECKAEG_PrivateKey const& other)
   : Public_Key(),
     EC_PublicKey(),
     Private_Key(),
     ECKAEG_PublicKey(),
     EC_PrivateKey(),
     PK_Key_Agreement_Key()
   {
   set_all_values(other);
   }

ECKAEG_PrivateKey const& ECKAEG_PrivateKey::operator= (ECKAEG_PrivateKey const& rhs)
   {
   set_all_values(rhs);
   return *this;
   }

MemoryVector<byte> ECKAEG_PrivateKey::public_value() const
   {
   return EC2OSP(public_point(), PointGFp::UNCOMPRESSED);
   }

/**
* Derive a key
*/
SecureVector<byte> ECKAEG_PrivateKey::derive_key(const byte key[],
                                                 u32bit key_len) const
   {
   MemoryVector<byte> key_x(key, key_len); // FIXME: nasty/slow
   PointGFp point = OS2ECP(key_x, public_point().get_curve());

   return m_eckaeg_core.agree(point);
   }

/**
* Derive a key
*/
SecureVector<byte> ECKAEG_PrivateKey::derive_key(const ECKAEG_PublicKey& key) const
   {
   affirm_init();
   key.affirm_init();

   return m_eckaeg_core.agree(key.public_point());
   }

}
