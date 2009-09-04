/**
* Engine for PK
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_PK_LOOKUP_H__
#define BOTAN_ENGINE_PK_LOOKUP_H__

#include <botan/bigint.h>
#include <botan/pow_mod.h>

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
  #include <botan/if_op.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa_op.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh_op.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr_op.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elg_op.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa_op.h>
  #include <botan/ec_dompar.h>
#endif

#if defined(BOTAN_HAS_ECKAEG)
  #include <botan/eckaeg_op.h>
  #include <botan/ec_dompar.h>
#endif

namespace Botan {

class Algorithm_Factory;
class Keyed_Filter;
class Modular_Exponentiator;

namespace Engine_Core {

/*
* Get an operation from an Engine
*/
Modular_Exponentiator* mod_exp(const BigInt&, Power_Mod::Usage_Hints);

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
IF_Operation* if_op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_DSA)
DSA_Operation* dsa_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
NR_Operation* nr_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_ELGAMAL)
ELG_Operation* elg_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
DH_Operation* dh_op(const DL_Group&, const BigInt&);
#endif

#if defined(BOTAN_HAS_ECDSA)
ECDSA_Operation* ecdsa_op(const EC_Domain_Params& dom_pars,
                          const BigInt& priv_key,
                          const PointGFp& pub_key);
#endif

#if defined(BOTAN_HAS_ECKAEG)
ECKAEG_Operation* eckaeg_op(const EC_Domain_Params& dom_pars,
                            const BigInt& priv_key,
                            const PointGFp& pub_key);
#endif

}

}

#endif
