/*
* ECKAEG Operation
* (C) 2007 FlexSecure GmbH
*     2008-2010 Jack Lloyd
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
   BigInt cofactor = m_dom_pars.get_cofactor();
   BigInt n = m_dom_pars.get_order();

   BigInt l = inverse_mod(cofactor, n);

   PointGFp S = cofactor * i;
   S *= (m_priv_key * l) % n;

   S.check_invariants();

   return BigInt::encode_1363(S.get_affine_x(),
                              S.get_curve().get_p().bytes());
   }

}
