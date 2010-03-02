/*
* ECKAEG implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eckaeg.h>

namespace Botan {

ECKAEG_PublicKey::ECKAEG_PublicKey(const EC_Domain_Params& dom_par,
                                   const PointGFp& pub_point)
   {
   domain_params = dom_par;
   public_key = pub_point;

   if(domain().get_curve() != public_point().get_curve())
      throw Invalid_Argument("ECKAEG_PublicKey: curve mismatch in constructor");
   }

ECKAEG_PrivateKey::ECKAEG_PrivateKey(RandomNumberGenerator& rng,
                                     const EC_Domain_Params& dom_pars)
   {
   domain_params = dom_pars;
   generate_private_key(rng);
   }

/**
* Derive a key
*/
SecureVector<byte> ECKAEG_PrivateKey::derive_key(const byte key[],
                                                 u32bit key_len) const
   {
   MemoryVector<byte> key_x(key, key_len); // FIXME: nasty/slow
   PointGFp point = OS2ECP(key_x, public_point().get_curve());

   return derive_key(point);
   }

/**
* Derive a key
*/
SecureVector<byte> ECKAEG_PrivateKey::derive_key(const ECKAEG_PublicKey& key) const
   {
   return derive_key(key.public_point());
   }

/**
* Derive a key
*/
SecureVector<byte> ECKAEG_PrivateKey::derive_key(const PointGFp& point) const
   {
   const BigInt& cofactor = domain().get_cofactor();
   const BigInt& n = domain().get_order();

   BigInt l = inverse_mod(cofactor, n); // can precompute this

   PointGFp S = (cofactor * point) * (private_value() * l);
   S.check_invariants();

   return BigInt::encode_1363(S.get_affine_x(),
                              point.get_curve().get_p().bytes());
   }

}
