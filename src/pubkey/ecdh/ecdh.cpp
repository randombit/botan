/*
* ECDH implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdh.h>

namespace Botan {

/**
* Derive a key
*/
SecureVector<byte> ECDH_PrivateKey::derive_key(const byte key[],
                                               u32bit key_len) const
   {
   PointGFp point = OS2ECP(key, key_len, public_point().get_curve());
   return derive_key(point);
   }

/**
* Derive a key
*/
SecureVector<byte> ECDH_PrivateKey::derive_key(const ECDH_PublicKey& key) const
   {
   return derive_key(key.public_point());
   }

/**
* Derive a key
*/
SecureVector<byte> ECDH_PrivateKey::derive_key(const PointGFp& point) const
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
