/**
* SSE2 Assembly Engine
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_sse2.h>

#if defined(BOTAN_HAS_SHA1_SSE2)
  #include <botan/sha1_sse2.h>
#endif

namespace Botan {

HashFunction* SSE2_Assembler_Engine::find_hash(const SCAN_Name& request,
                                               Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_SHA1_SSE2)
   if(request.algo_name() == "SHA-160")
      return new SHA_160_SSE2;
#endif

   return 0;
   }

}
