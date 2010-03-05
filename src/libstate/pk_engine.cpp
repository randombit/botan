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
