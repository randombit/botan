/**
* SIMD Engine
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/simd_engine.h>
#include <botan/simd_32.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_SERPENT_SIMD)
  #include <botan/serp_simd.h>
#endif

#if defined(BOTAN_HAS_XTEA_SIMD)
  #include <botan/xtea_simd.h>
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
  #include <botan/sha1_sse2.h>
#endif

namespace Botan {

BlockCipher*
SIMD_Engine::find_block_cipher(const SCAN_Name& request,
                               Algorithm_Factory&) const
   {
   if(!SIMD_32::enabled())
      return 0;

#if defined(BOTAN_HAS_SERPENT_SIMD)
   if(request.algo_name() == "Serpent")
      return new Serpent_SIMD;
#endif

#if defined(BOTAN_HAS_XTEA_SIMD)
   if(request.algo_name() == "XTEA")
      return new XTEA_SIMD;
#endif

   return 0;
   }

HashFunction*
SIMD_Engine::find_hash(const SCAN_Name& request,
                       Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_SHA1_SSE2)
   if(request.algo_name() == "SHA-160" && CPUID::has_sse2())
      return new SHA_160_SSE2;
#endif

   return 0;
   }

}
