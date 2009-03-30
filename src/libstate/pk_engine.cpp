/*
* PK Engine Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pk_engine.h>
#include <botan/libstate.h>
#include <botan/engine.h>

namespace Botan {

namespace Engine_Core {

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)
/*
* Acquire an IF op
*/
IF_Operation* if_op(const BigInt& e, const BigInt& n, const BigInt& d,
                    const BigInt& p, const BigInt& q, const BigInt& d1,
                    const BigInt& d2, const BigInt& c)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      IF_Operation* op = engine->if_op(e, n, d, p, q, d1, d2, c);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::if_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_DSA)
/*
* Acquire a DSA op
*/
DSA_Operation* dsa_op(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      DSA_Operation* op = engine->dsa_op(group, y, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::dsa_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
/*
* Acquire a NR op
*/
NR_Operation* nr_op(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      NR_Operation* op = engine->nr_op(group, y, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::nr_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_ELGAMAL)
/*
* Acquire an ElGamal op
*/
ELG_Operation* elg_op(const DL_Group& group, const BigInt& y, const BigInt& x)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      ELG_Operation* op = engine->elg_op(group, y, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::elg_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
/*
* Acquire a DH op
*/
DH_Operation* dh_op(const DL_Group& group, const BigInt& x)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      DH_Operation* op = engine->dh_op(group, x);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::dh_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_ECDSA)
/*
* Acquire an ECDSA op
*/
ECDSA_Operation* ecdsa_op(const EC_Domain_Params& dom_pars,
                          const BigInt& priv_key,
                          const PointGFp& pub_key)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      ECDSA_Operation* op = engine->ecdsa_op(dom_pars, priv_key, pub_key);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::ecdsa_op: Unable to find a working engine");
   }
#endif

#if defined(BOTAN_HAS_ECKAEG)
/*
* Acquire a ECKAEG op
*/
ECKAEG_Operation* eckaeg_op(const EC_Domain_Params& dom_pars,
                            const BigInt& priv_key,
                            const PointGFp& pub_key)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      ECKAEG_Operation* op = engine->eckaeg_op(dom_pars, priv_key, pub_key);
      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::eckaeg_op: Unable to find a working engine");
   }
#endif

/*
* Acquire a modular exponentiator
*/
Modular_Exponentiator* mod_exp(const BigInt& n, Power_Mod::Usage_Hints hints)
   {
   Algorithm_Factory::Engine_Iterator i(global_state().algorithm_factory());

   while(const Engine* engine = i.next())
      {
      Modular_Exponentiator* op = engine->mod_exp(n, hints);

      if(op)
         return op;
      }

   throw Lookup_Error("Engine_Core::mod_exp: Unable to find a working engine");
   }

}

}
