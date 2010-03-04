/*
* PK Operations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/default_engine.h>

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
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

namespace Botan {

PK_Ops::KA_Operation*
Default_Engine::get_key_agreement_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(const DH_PrivateKey* dh = dynamic_cast<const DH_PrivateKey*>(&key))
      return new DH_KA_Operation(*dh);
#endif

#if defined(BOTAN_HAS_ECDH)
   if(const ECDH_PrivateKey* ecdh = dynamic_cast<const ECDH_PrivateKey*>(&key))
      return new ECDH_KA_Operation(*ecdh);
#endif

   return 0;
   }

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

}
