/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/aes_isa_engine.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_AES_NI)
  #include <botan/aes_ni.h>
#endif

namespace Botan {

BlockCipher*
AES_ISA_Engine::find_block_cipher(const SCAN_Name& request,
                                  Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_AES_NI)
   if(CPUID::has_aes_ni())
      {
      if(request.algo_name() == "AES-128")
         return new AES_128_NI;
      if(request.algo_name() == "AES-192")
         return new AES_192_NI;
      if(request.algo_name() == "AES-256")
         return new AES_256_NI;
      }
#endif

   return nullptr;
   }

}
