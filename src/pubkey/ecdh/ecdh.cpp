/*
* ECDH implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdh.h>
#include <botan/internal/assert.h>

namespace Botan {

ECDH_KA_Operation::ECDH_KA_Operation(const ECDH_PrivateKey& key) :
   curve(key.domain().get_curve()),
   cofactor(key.domain().get_cofactor())
   {
   l_times_priv = inverse_mod(cofactor, key.domain().get_order()) *
                  key.private_value();
   }

SecureVector<byte> ECDH_KA_Operation::agree(const byte w[], size_t w_len)
   {
   PointGFp point = OS2ECP(w, w_len, curve);

   PointGFp S = (cofactor * point) * l_times_priv;

   BOTAN_ASSERT(S.on_the_curve(),
                "ECDH agreed value not on the curve");

   return BigInt::encode_1363(S.get_affine_x(),
                              curve.get_p().bytes());
   }

}
