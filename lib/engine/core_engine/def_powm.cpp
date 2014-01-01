/*
* Modular Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/internal/def_powm.h>

namespace Botan {

/*
* Choose a modular exponentation algorithm
*/
Modular_Exponentiator*
Core_Engine::mod_exp(const BigInt& n, Power_Mod::Usage_Hints hints) const
   {
   if(n.is_odd())
      return new Montgomery_Exponentiator(n, hints);
   return new Fixed_Window_Exponentiator(n, hints);
   }

}
