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

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elg_op.h>
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

#if defined(BOTAN_HAS_ELGAMAL)
ELG_Operation* elg_op(const DL_Group&, const BigInt&, const BigInt&);
#endif

}

}

#endif
