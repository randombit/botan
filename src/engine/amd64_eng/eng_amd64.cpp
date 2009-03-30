/**
* AMD64 Assembly Implementation Engine
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_amd64.h>

#if defined(BOTAN_HAS_SHA1_AMD64)
  #include <botan/sha1_amd64.h>
#endif

namespace Botan {

HashFunction* AMD64_Assembler_Engine::find_hash(const SCAN_Name& request,
                                                Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_SHA1_AMD64)
   if(request.algo_name() == "SHA-160")
      return new SHA_160_AMD64;
#endif

   return 0;
   }

}
