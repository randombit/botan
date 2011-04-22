/*
* Assembly Implementation Engine
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/asm_engine.h>

#if defined(BOTAN_HAS_SERPENT_X86_32)
  #include <botan/serp_x86_32.h>
#endif

#if defined(BOTAN_HAS_MD4_X86_32)
  #include <botan/md4_x86_32.h>
#endif

#if defined(BOTAN_HAS_MD5_X86_32)
  #include <botan/md5_x86_32.h>
#endif

#if defined(BOTAN_HAS_SHA1_X86_64)
  #include <botan/sha1_x86_64.h>
#endif

#if defined(BOTAN_HAS_SHA1_X86_32)
  #include <botan/sha1_x86_32.h>
#endif

namespace Botan {

BlockCipher*
Assembler_Engine::find_block_cipher(const SCAN_Name& request,
                                    Algorithm_Factory&) const
   {
   if(request.algo_name() == "Serpent")
      {
#if defined(BOTAN_HAS_SERPENT_X86_32)
      return new Serpent_X86_32;
#endif
      }

   return 0;
   }

HashFunction*
Assembler_Engine::find_hash(const SCAN_Name& request,
                            Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_MD4_X86_32)
   if(request.algo_name() == "MD4")
      return new MD4_X86_32;
#endif

#if defined(BOTAN_HAS_MD5_X86_32)
   if(request.algo_name() == "MD5")
      return new MD5_X86_32;
#endif

   if(request.algo_name() == "SHA-160")
      {
#if defined(BOTAN_HAS_SHA1_X86_64)
         return new SHA_160_X86_64;
#elif defined(BOTAN_HAS_SHA1_X86_32)
         return new SHA_160_X86_32;
#endif
      }

   return 0;
   }

}
