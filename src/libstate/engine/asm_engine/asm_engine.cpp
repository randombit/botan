/*************************************************
* Assembly Implementation Engine Header File     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/asm_engine.h>
#include <botan/hash.h>

#if defined(BOTAN_HAS_SERPENT_IA32)
  #include <botan/serp_ia32.h>
#endif

#if defined(BOTAN_HAS_MD4_IA32)
  #include <botan/md4_ia32.h>
#endif

#if defined(BOTAN_HAS_MD5_IA32)
  #include <botan/md5_ia32.h>
#endif

#if defined(BOTAN_HAS_SHA1_IA32)
  #include <botan/sha1_ia32.h>
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
  #include <botan/sha1_sse2.h>
#endif

#if defined(BOTAN_HAS_SHA1_AMD64)
  #include <botan/sha1_amd64.h>
#endif

namespace Botan {

BlockCipher*
Assembler_Engine::find_block_cipher(const SCAN_Name& request,
                                  Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_SERPENT_IA32)
   if(request.algo_name() == "Serpent")
      return new Serpent_IA32;
#endif

   return 0;
   }

HashFunction* Assembler_Engine::find_hash(const SCAN_Name& request,
                                          Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_MD4_IA32)
   if(request.algo_name() == "MD4")
      return new MD4_IA32;
#endif

#if defined(BOTAN_HAS_MD5_IA32)
   if(request.algo_name() == "MD5")
      return new MD5_IA32;
#endif

#if defined(BOTAN_HAS_SHA1_SSE2) || \
    defined(BOTAN_HAS_SHA1_AMD64) || \
    defined(BOTAN_HAS_SHA1_IA32)

   if(request.algo_name() == "SHA-160")
      {
#if defined(BOTAN_HAS_SHA1_SSE2)
      return new SHA_160_SSE2;
#elif defined(BOTAN_HAS_SHA1_AMD64)
      return new SHA_160_AMD64;
#elif defined(BOTAN_HAS_SHA1_IA32)
      return new SHA_160_IA32;
#endif
      }
#endif

   return 0;
   }

}
