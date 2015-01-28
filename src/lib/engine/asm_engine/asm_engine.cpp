/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/asm_engine.h>
#include <botan/algo_registry.h>

namespace Botan {

BlockCipher*
Assembler_Engine::find_block_cipher(const SCAN_Name& request,
                                    Algorithm_Factory&) const
   {
   auto& block_cipher = Algo_Registry<BlockCipher>::global_registry();

   if(BlockCipher* c = block_cipher.make(request, "x86-32"))
      return c;

   return nullptr;
   }

HashFunction*
Assembler_Engine::find_hash(const SCAN_Name& request,
                            Algorithm_Factory&) const
   {
   auto& hash_fns = Algo_Registry<HashFunction>::global_registry();
   if(HashFunction* c = hash_fns.make(request, "x86-64"))
      return c;

   if(HashFunction* c = hash_fns.make(request, "x86-32"))
      return c;

   return nullptr;
   }

}
