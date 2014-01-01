/*
* Default provider weights for Algorithm_Cache
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/algo_cache.h>

namespace Botan {

/**
* Return a static provider weighing
*/
size_t static_provider_weight(const std::string& prov_name)
   {
   /*
   * Prefer asm over C++, but prefer anything over OpenSSL or GNU MP; to use
   * them, set the provider explicitly for the algorithms you want
   */

   if(prov_name == "aes_isa") return 9;
   if(prov_name == "simd") return 8;
   if(prov_name == "asm") return 7;

   if(prov_name == "core") return 5;

   if(prov_name == "openssl") return 2;
   if(prov_name == "gmp") return 1;

   return 0; // other/unknown
   }

}
