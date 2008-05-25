/*************************************************
* Modular Exponentiation Source File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/eng_def.h>
#include <botan/def_powm.h>




namespace Botan {

/*************************************************
* Choose a modular exponentation algorithm       *
*************************************************/
std::auto_ptr<Modular_Exponentiator>
Default_Engine::mod_exp(const BigInt& n, Power_Mod::Usage_Hints hints) const
   {
   if(n.is_odd())
      return std::auto_ptr<Modular_Exponentiator>(new Montgomery_Exponentiator(n, hints));
   return std::auto_ptr<Modular_Exponentiator>(new Fixed_Window_Exponentiator(n, hints));
   }

}
