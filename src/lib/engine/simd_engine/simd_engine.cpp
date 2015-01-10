/*
* SIMD Engine
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/simd_engine.h>
#include <botan/internal/simd_32.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_AES_SSSE3)
  #include <botan/aes_ssse3.h>
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
  #include <botan/serp_simd.h>
#endif

#if defined(BOTAN_HAS_THREEFISH_512_AVX2)
  #include <botan/threefish_avx2.h>
#endif

#if defined(BOTAN_HAS_NOEKEON_SIMD)
  #include <botan/noekeon_simd.h>
#endif

#if defined(BOTAN_HAS_XTEA_SIMD)
  #include <botan/xtea_simd.h>
#endif

#if defined(BOTAN_HAS_IDEA_SSE2)
  #include <botan/idea_sse2.h>
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
  #include <botan/sha1_sse2.h>
#endif

namespace Botan {

BlockCipher*
SIMD_Engine::find_block_cipher(const SCAN_Name& request,
                               Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_AES_SSSE3)
   if(request.algo_name() == "AES-128" && CPUID::has_ssse3())
      return new AES_128_SSSE3;
   if(request.algo_name() == "AES-192" && CPUID::has_ssse3())
      return new AES_192_SSSE3;
   if(request.algo_name() == "AES-256" && CPUID::has_ssse3())
      return new AES_256_SSSE3;
#endif

#if defined(BOTAN_HAS_IDEA_SSE2)
   if(request.algo_name() == "IDEA" && CPUID::has_sse2())
      return new IDEA_SSE2;
#endif

#if defined(BOTAN_HAS_NOEKEON_SIMD)
   if(request.algo_name() == "Noekeon" && SIMD_32::enabled())
      return new Noekeon_SIMD;
#endif

#if defined(BOTAN_HAS_THREEFISH_512_AVX2)
   if(request.algo_name() == "Threefish-512" && CPUID::has_avx2())
      return new Threefish_512_AVX2;
#endif

#if defined(BOTAN_HAS_SERPENT_SIMD)
   if(request.algo_name() == "Serpent" && SIMD_32::enabled())
      return new Serpent_SIMD;
#endif

#if defined(BOTAN_HAS_XTEA_SIMD)
   if(request.algo_name() == "XTEA" && SIMD_32::enabled())
      return new XTEA_SIMD;
#endif

   return nullptr;
   }

HashFunction*
SIMD_Engine::find_hash(const SCAN_Name& request,
                       Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_SHA1_SSE2)
   if(request.algo_name() == "SHA-160" && CPUID::has_sse2())
      return new SHA_160_SSE2;
#endif

   BOTAN_UNUSED(request);

   return nullptr;
   }

}
