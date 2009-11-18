/*
* ECDSA Operation
* (C) 2007 FlexSecure GmbH
*     2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdsa_op.h>
#include <botan/numthry.h>

#include <stdio.h>
#include <iostream>

namespace Botan {

Default_ECDSA_Op::Default_ECDSA_Op(const EC_Domain_Params& domain,
                                   const BigInt& priv,
                                   const PointGFp& pub) :
   dom_pars(domain), pub_key(pub), priv_key(priv)
   {
   }

bool Default_ECDSA_Op::verify(const byte msg[], u32bit msg_len,
                              const byte sig[], u32bit sig_len) const
   {
   const BigInt& n = dom_pars.get_order();

   if(sig_len != n.bytes()*2)
      return false;

   // NOTE: it is not checked whether the public point is set
   if(dom_pars.get_curve().get_p() == 0)
      throw Internal_Error("domain parameters not set");

   BigInt e(msg, msg_len);

   BigInt r(sig, sig_len / 2);
   BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r < 0 || r >= n || s < 0 || s >= n)
      return false;

   BigInt w = inverse_mod(s, n);

   PointGFp R = w * (e * dom_pars.get_base_point() + r*pub_key);
   if(R.is_zero())
      return false;

   BigInt x = R.get_affine_x().get_value();

   return (x % n == r);
   }

SecureVector<byte> Default_ECDSA_Op::sign(const byte msg[], u32bit msg_len,
                                          const BigInt& k) const
   {
   if(priv_key == 0)
      throw Internal_Error("Default_ECDSA_Op::sign(): no private key");

   const BigInt& n = dom_pars.get_order();

   if(n == 0)
      throw Internal_Error("Default_ECDSA_Op::sign(): domain parameters not set");

   BigInt e(msg, msg_len);

   PointGFp k_times_P(dom_pars.get_base_point());
   k_times_P.mult_this_secure(k, n, n-1);
   k_times_P.check_invariants();
   BigInt r = k_times_P.get_affine_x().get_value() % n;

   if(r == 0)
      throw Internal_Error("Default_ECDSA_Op::sign: r was zero");

   BigInt k_inv = inverse_mod(k, n);

   BigInt s(r);
   s *= priv_key;
   s += e;
   s *= k_inv;
   s %= n;

   SecureVector<byte> output(2*n.bytes());
   r.binary_encode(output + (output.size() / 2 - r.bytes()));
   s.binary_encode(output + (output.size() - s.bytes()));
   return output;
   }

}
