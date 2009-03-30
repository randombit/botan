/*
* ECDSA Operation
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecdsa_op.h>
#include <botan/numthry.h>

namespace Botan {

bool Default_ECDSA_Op::verify(const byte signature[], u32bit sig_len,
                              const byte message[], u32bit mess_len) const
   {
   if(sig_len % 2 != 0)
      throw Invalid_Argument("Erroneous length of signature");

   //NOTE: it is not checked whether the public point is set
   if(m_dom_pars.get_curve().get_p() == 0)
      throw Internal_Error("domain parameters not set");

   BigInt e(message, mess_len);

   u32bit rs_len = sig_len/2;
   SecureVector<byte> sv_r;
   SecureVector<byte> sv_s;
   sv_r.set(signature, rs_len);
   sv_s.set(signature+rs_len, rs_len);
   BigInt r = BigInt::decode ( sv_r, sv_r.size());
   BigInt s = BigInt::decode (sv_s, sv_s.size());

   if(r < 0 || r >= m_dom_pars.get_order())
      throw Invalid_Argument("r in ECDSA signature has an illegal value");

   if(s < 0 || s >= m_dom_pars.get_order())
      throw Invalid_Argument("s in ECDSA signature has an illegal value");

   BigInt w = inverse_mod(s, m_dom_pars.get_order());

   PointGFp R = w*(e*m_dom_pars.get_base_point() + r*m_pub_key);
   if(R.is_zero())
      return false;

   BigInt x = R.get_affine_x().get_value();
   bool result = (x % m_dom_pars.get_order() == r);
   return result;
   }

SecureVector<byte> Default_ECDSA_Op::sign(const byte message[],
                                          u32bit mess_len,
                                          RandomNumberGenerator& rng) const
   {
   if(m_priv_key == 0)
      throw Internal_Error("Default_ECDSA_Op::sign(): no private key");

   if(m_dom_pars.get_curve().get_p() == 0)
      throw Internal_Error("Default_ECDSA_Op::sign(): domain parameters not set");

   BigInt e(message, mess_len);

   // generate k
   BigInt k;
   BigInt r(0);
   const BigInt n(m_dom_pars.get_order());
   while(r == 0)
      {
      k = BigInt::random_integer(rng, 1, n);

      PointGFp k_times_P(m_dom_pars.get_base_point());
      k_times_P.mult_this_secure(k, n, n-1);
      k_times_P.check_invariants();
      r =  k_times_P.get_affine_x().get_value() % n;
      }
   BigInt k_inv = inverse_mod(k, n);

   // use randomization against attacks on s:
   // a = k_inv * (r*(d + x) + e) mod n
   // b = k_inv * r * x mod n
   // s = a - b mod n
   // where x is a random integer

#if defined(CMS_RAND)
   BigInt x = BigInt::random_integer(0, n);
   BigInt s = m_priv_key + x; // obscure the secret from the beginning
   // all following operations thus are randomized
   s *= r;
   s += e;
   s *= k_inv;
   s %= n;

   BigInt b = x; // again, start with the random number
   b *= r;
   b *= k_inv;
   b %= n;
   s -= b; // s = a - b
   if(s <= 0) // s %= n
      {
      s += n;
      }
#else // CMS_RAND
   // no countermeasure here
   BigInt s(r);
   s *= m_priv_key;
   s += e;
   s *= k_inv;
   s %= n;

#endif // CMS_RAND

   SecureVector<byte> sv_r = BigInt::encode_1363 ( r, m_dom_pars.get_order().bytes() );
   SecureVector<byte> sv_s = BigInt::encode_1363 ( s, m_dom_pars.get_order().bytes() );

   SecureVector<byte> result(sv_r);
   result.append(sv_s);
   return result;
   }

Default_ECDSA_Op::Default_ECDSA_Op(const EC_Domain_Params& dom_pars, const BigInt& priv_key, const PointGFp& pub_key)
   : m_dom_pars(dom_pars),
     m_pub_key(pub_key),
     m_priv_key(priv_key)
   {

   }

}

