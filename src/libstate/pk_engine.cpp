/*
* PK Engine Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/pk_engine.h>
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
