/*
* MAC Lookup
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/core_engine.h>
#include <botan/scan_name.h>
#include <botan/algo_registry.h>

namespace Botan {

/*
* Look for an algorithm with this name
*/
MessageAuthenticationCode*
Core_Engine::find_mac(const SCAN_Name& request,
                      Algorithm_Factory&) const
   {
   if(MessageAuthenticationCode* m = Algo_Registry<MessageAuthenticationCode>::global_registry().make(request, "builtin"))
      return m;

   return nullptr;
   }

}
