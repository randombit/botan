/*
* PK Operations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/def_eng.h>

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
  #include <botan/if_op.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa_op.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr_op.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elg_op.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh_op.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa_op.h>
#endif

#if defined(BOTAN_HAS_ECKAEG)
  #include <botan/eckaeg_op.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
/*
* Acquire an IF op
*/
IF_Operation* Default_Engine::if_op(const BigInt& e, const BigInt& n,
                                    const BigInt& d, const BigInt& p,
                                    const BigInt& q, const BigInt& d1,
                                    const BigInt& d2, const BigInt& c) const
   {
   return new Default_IF_Op(e, n, d, p, q, d1, d2, c);
   }
#endif

#if defined(BOTAN_HAS_DSA)
/*
* Acquire a DSA op
*/
DSA_Operation* Default_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new Default_DSA_Op(group, y, x);
   }
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
/*
* Acquire a NR op
*/
NR_Operation* Default_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                    const BigInt& x) const
   {
   return new Default_NR_Op(group, y, x);
   }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
/*
* Acquire an ElGamal op
*/
ELG_Operation* Default_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new Default_ELG_Op(group, y, x);
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
/*
* Acquire a DH op
*/
DH_Operation* Default_Engine::dh_op(const DL_Group& group,
                                    const BigInt& x) const
   {
   return new Default_DH_Op(group, x);
   }
#endif

#if defined(BOTAN_HAS_ECDSA)
/*
* Acquire a ECDSA op
*/
ECDSA_Operation* Default_Engine::ecdsa_op(const EC_Domain_Params& dom_pars,
                                          const BigInt& priv_key,
                                          const PointGFp& pub_key) const
   {
   return new Default_ECDSA_Op(dom_pars, priv_key, pub_key);
   }
#endif

#if defined(BOTAN_HAS_ECKAEG)
/*
* Acquire a ECKAEG op
*/
ECKAEG_Operation* Default_Engine::eckaeg_op(const EC_Domain_Params& dom_pars,
                                            const BigInt& priv_key,
                                            const PointGFp& pub_key) const
   {
   return new Default_ECKAEG_Op(dom_pars, priv_key, pub_key);
   }
#endif

}
