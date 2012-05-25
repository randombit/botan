/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdsa.h>
#include <botan/keypair.h>

namespace Botan {

bool ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng,
                                 bool strong) const
   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-1)");
   }

ECDSA_Signature_Operation::ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa) :
   base_point(ecdsa.domain().get_base_point()),
   order(ecdsa.domain().get_order()),
   x(ecdsa.private_value()),
   mod_order(order)
   {
   }

secure_vector<byte>
ECDSA_Signature_Operation::sign(const byte msg[], size_t msg_len,
                                RandomNumberGenerator& rng)
   {
   rng.add_entropy(msg, msg_len);

   BigInt m(msg, msg_len);

   BigInt r = 0, s = 0;

   while(r == 0 || s == 0)
      {
      // This contortion is necessary for the tests
      BigInt k;
      k.randomize(rng, order.bits());

      while(k >= order)
         k.randomize(rng, order.bits() - 1);

      PointGFp k_times_P = base_point * k;
      r = mod_order.reduce(k_times_P.get_affine_x());
      s = mod_order.multiply(inverse_mod(k, order), mul_add(x, r, m));
      }

   secure_vector<byte> output(2*order.bytes());
   r.binary_encode(&output[output.size() / 2 - r.bytes()]);
   s.binary_encode(&output[output.size() - s.bytes()]);
   return output;
   }

ECDSA_Verification_Operation::ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa) :
   base_point(ecdsa.domain().get_base_point()),
   public_point(ecdsa.public_point()),
   order(ecdsa.domain().get_order())
   {
   }

bool ECDSA_Verification_Operation::verify(const byte msg[], size_t msg_len,
                                          const byte sig[], size_t sig_len)
   {
   if(sig_len != order.bytes()*2)
      return false;

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= order || s <= 0 || s >= order)
      return false;

   BigInt w = inverse_mod(s, order);

   PointGFp R = w * multi_exponentiate(base_point, e,
                                       public_point, r);

   if(R.is_zero())
      return false;

   return (R.get_affine_x() % order == r);
   }

}
