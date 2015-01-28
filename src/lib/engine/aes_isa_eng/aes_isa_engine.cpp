/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes_isa_engine.h>
#include <botan/algo_registry.h>

namespace Botan {

BlockCipher*
AES_ISA_Engine::find_block_cipher(const SCAN_Name& request,
                                  Algorithm_Factory&) const
   {
   if(BlockCipher* c = Algo_Registry<BlockCipher>::global_registry().make(request, "aes_ni"))
      return c;

   return nullptr;
   }

}
