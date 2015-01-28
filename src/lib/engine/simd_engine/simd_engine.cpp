/*
* SIMD Engine
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/simd_engine.h>
#include <botan/algo_registry.h>
#include <botan/cpuid.h>

namespace Botan {

BlockCipher*
SIMD_Engine::find_block_cipher(const SCAN_Name& request,
                               Algorithm_Factory&) const
   {
   auto& block_cipher = Algo_Registry<BlockCipher>::global_registry();

   if(BlockCipher* c = block_cipher.make(request, "avx2"))
      return c;

   if(BlockCipher* c = block_cipher.make(request, "ssse3"))
      return c;

   if(BlockCipher* c = block_cipher.make(request, "sse2"))
      return c;

   if(BlockCipher* c = block_cipher.make(request, "simd32"))
      return c;

   return nullptr;
   }

HashFunction*
SIMD_Engine::find_hash(const SCAN_Name& request,
                       Algorithm_Factory&) const
   {
   if(HashFunction* c = Algo_Registry<HashFunction>::global_registry().make(request, "sse2"))
      return c;

   return nullptr;
   }

}
