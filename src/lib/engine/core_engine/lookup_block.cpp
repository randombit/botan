/*
* Block Cipher Lookup
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
BlockCipher* Core_Engine::find_block_cipher(const SCAN_Name& request,
                                            Algorithm_Factory&) const
   {
   if(BlockCipher* c = Algo_Registry<BlockCipher>::global_registry().make(request, "builtin"))
      return c;

   return nullptr;
   }

}
