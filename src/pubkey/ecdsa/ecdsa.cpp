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

bool ECDSA_PublicKey::verify(const byte msg[], u32bit msg_len,
                             const byte sig[], u32bit sig_len) const
   {
   const BigInt& n = domain().get_order();

   if(n == 0)
      throw Invalid_State("ECDSA_PublicKey::verify: Not initialized");

   if(sig_len != n.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r < 0 || r >= n || s < 0 || s >= n)
      return false;

   BigInt w = inverse_mod(s, n);

   PointGFp R = w * (e * domain().get_base_point() + r*public_point());
   if(R.is_zero())
      return false;

   return (R.get_affine_x() % n == r);
   }

SecureVector<byte> ECDSA_PrivateKey::sign(const byte msg[],
                                          u32bit msg_len,
                                          RandomNumberGenerator& rng) const
   {
   const BigInt& n = domain().get_order();

   if(n == 0 || private_value() == 0)
      throw Invalid_State("ECDSA_PrivateKey::sign: Not initialized");

   BigInt k;
   do
      k.randomize(rng, n.bits()-1);
   while(k >= n);

   BigInt e(msg, msg_len);

   PointGFp k_times_P = domain().get_base_point() * k;
   BigInt r = k_times_P.get_affine_x() % n;

   if(r == 0)
      throw Internal_Error("Default_ECDSA_Op::sign: r was zero");

   BigInt k_inv = inverse_mod(k, n);

   BigInt s = (((r * private_value()) + e) * k_inv) % n;

   SecureVector<byte> output(2*n.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

ECDSA_Signature_Operation::ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa) :
   base_point(ecdsa.domain().get_base_point()),
   order(ecdsa.domain().get_order()),
   x(ecdsa.private_value())
   {
   }

SecureVector<byte> ECDSA_Signature_Operation::sign(const byte msg[],
                                                   u32bit msg_len,
                                                   RandomNumberGenerator& rng)
   {
   rng.add_entropy(msg, msg_len);

   BigInt k;
   do
      k.randomize(rng, order.bits()-1);
   while(k >= order);

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

}
