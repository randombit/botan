/*
* Modular Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/def_eng.h>
#include <botan/def_powm.h>

namespace Botan {

/*
* Choose a modular exponentation algorithm
*/
Modular_Exponentiator*
Default_Engine::mod_exp(const BigInt& n, Power_Mod::Usage_Hints hints) const
   {
   if(n.is_odd())
      return new Montgomery_Exponentiator(n, hints);
   return new Fixed_Window_Exponentiator(n, hints);
   }

}
