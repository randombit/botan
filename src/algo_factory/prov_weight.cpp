/**
* Default provider weights for Algorithm_Cache
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/algo_cache.h>

namespace Botan {

/**
* Return a static provider weighing
*/
u32bit static_provider_weight(const std::string& prov_name)
   {
   /*
   * Prefer asm over C++, but prefer anything over OpenSSL or GNU MP; to use
   * them, set the provider explicitly for the algorithms you want
   */

   if(prov_name == "core") return 5;
   if(prov_name == "ia32") return 6;
   if(prov_name == "amd64") return 7;
   if(prov_name == "sse2") return 8;

   if(prov_name == "openssl") return 2;
   if(prov_name == "gmp") return 1;

   return 0; // other
   }

}
