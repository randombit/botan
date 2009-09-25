/**
* SSE2 Assembly Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_sse2.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_SHA1_SSE2)
  #include <botan/sha1_sse2.h>
#endif

#if defined(BOTAN_HAS_SERPENT_SSE2)
  #include <botan/serp_sse2.h>
#endif

namespace Botan {

BlockCipher*
SSE2_Assembler_Engine::find_block_cipher(const SCAN_Name& request,
                                         Algorithm_Factory&) const
   {
   if(!CPUID::has_sse2())
      return 0;

#if defined(BOTAN_HAS_SERPENT_SSE2)
   if(request.algo_name() == "Serpent")
      return new Serpent_SSE2;
#endif

   return 0;
   }

HashFunction*
SSE2_Assembler_Engine::find_hash(const SCAN_Name& request,
                                 Algorithm_Factory&) const
   {
   if(!CPUID::has_sse2())
      return 0;

#if defined(BOTAN_HAS_SHA1_SSE2)
   if(request.algo_name() == "SHA-160")
      return new SHA_160_SSE2;
#endif

   return 0;
   }

}
