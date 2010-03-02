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
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/secmem.h>
#include <botan/point_gfp.h>

namespace Botan {

void ECKAEG_PublicKey::X509_load_hook()
   {
   EC_PublicKey::X509_load_hook();
   m_eckaeg_core = ECKAEG_Core(domain(), 0, public_point());
   }

ECKAEG_PublicKey::ECKAEG_PublicKey(const EC_Domain_Params& dom_par,
                                   const PointGFp& pub_point)
   {
   domain_params = dom_par;
   public_key = pub_point;

   if(domain().get_curve() != pub_point.get_curve())
      throw Invalid_Argument("ECKAEG_PublicKey: curve mismatch in constructor");

   m_eckaeg_core = ECKAEG_Core(domain(), 0, public_point());
   }

void ECKAEG_PrivateKey::PKCS8_load_hook(bool generated)
   {
   EC_PrivateKey::PKCS8_load_hook(generated);
   m_eckaeg_core = ECKAEG_Core(domain(), private_value(), public_point());
   }

MemoryVector<byte> ECKAEG_PrivateKey::public_value() const
   {
   return EC2OSP(public_point(), PointGFp::UNCOMPRESSED);
   }

ECKAEG_PrivateKey::ECKAEG_PrivateKey(RandomNumberGenerator& rng,
                                     const EC_Domain_Params& dom_pars)
   {
   domain_params = dom_pars;
   generate_private_key(rng);
   m_eckaeg_core = ECKAEG_Core(domain(), private_value(), public_point());
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
   return m_eckaeg_core.agree(key.public_point());
   }

}
