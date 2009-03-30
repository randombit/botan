/*
* ECKAEG Operation
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eckaeg_op.h>
#include <botan/numthry.h>

namespace Botan {

Default_ECKAEG_Op::Default_ECKAEG_Op(const EC_Domain_Params& dom_pars,
                                     const BigInt& priv_key,
                                     const PointGFp& pub_key)
   : m_dom_pars(dom_pars),
     m_pub_key(pub_key),
     m_priv_key(priv_key)
   {
   }

SecureVector<byte> Default_ECKAEG_Op::agree(const PointGFp& i) const
   {
   BigInt cofactor(m_dom_pars.get_cofactor());
   BigInt n = m_dom_pars.get_order();
   BigInt l(inverse_mod(cofactor,n)); // l=h^-1 mod n
   PointGFp Q(cofactor*i); // q = h*Pb
   PointGFp S(Q);
   BigInt group_order = m_dom_pars.get_cofactor() * n;
   S.mult_this_secure((m_priv_key*l)%n, group_order, n-1);
   S.check_invariants();
   return FE2OSP(S.get_affine_x()); // fe2os(xs)
   }

}
