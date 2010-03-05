/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdsa.h>

namespace Botan {

ECDSA_Signature_Operation::ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa) :
   base_point(ecdsa.domain().get_base_point()),
   order(ecdsa.domain().get_order()),
   x(ecdsa.private_value())
   {
   }

SecureVector<byte>
ECDSA_Signature_Operation::sign(const byte msg[], u32bit msg_len,
                                RandomNumberGenerator& rng) const
   {
   rng.add_entropy(msg, msg_len);

   BigInt k;
   k.randomize(rng, order.bits());

   while(k >= order)
      k.randomize(rng, order.bits() - 1);

   BigInt e(msg, msg_len);

   PointGFp k_times_P = base_point * k;
   BigInt r = k_times_P.get_affine_x() % order;

   if(r == 0)
      throw Internal_Error("ECDSA_Signature_Operation: r was zero");

   BigInt k_inv = inverse_mod(k, order);

   BigInt s = (((r * x) + e) * k_inv) % order;

   SecureVector<byte> output(2*order.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

ECDSA_Verification_Operation::ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa) :
   base_point(ecdsa.domain().get_base_point()),
   public_point(ecdsa.public_point()),
   order(ecdsa.domain().get_order())
   {
   }

bool ECDSA_Verification_Operation::verify(const byte msg[], u32bit msg_len,
                                          const byte sig[], u32bit sig_len) const
   {
   if(sig_len != order.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r < 0 || r >= order || s < 0 || s >= order)
      return false;

   BigInt w = inverse_mod(s, order);

   PointGFp R = w * (e * base_point + r * public_point);
   if(R.is_zero())
      return false;

   return (R.get_affine_x() % order == r);
   }

}
