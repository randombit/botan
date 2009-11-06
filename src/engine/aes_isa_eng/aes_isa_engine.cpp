/*
* Engine for AES instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/aes_isa_engine.h>
#include <botan/cpuid.h>

#if defined(BOTAN_HAS_AES_INTEL)
  #include <botan/aes_intel.h>
#endif

#if defined(BOTAN_HAS_AES_VIA)
  #include <botan/aes_via.h>
#endif

namespace Botan {

BlockCipher*
AES_ISA_Engine::find_block_cipher(const SCAN_Name& request,
                                  Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_AES_INTEL)
   if(CPUID::has_intel_aes())
      {
      if(request.algo_name() == "AES")
         return new AES_Intel;
      if(request.algo_name() == "AES-128")
         return new AES_Intel_128;
      if(request.algo_name() == "AES-192")
         return new AES_Intel_192;
      if(request.algo_name() == "AES-256")
         return new AES_Intel_256;
      }
#endif

#if defined(BOTAN_HAS_AES_VIA)
   if(CPUID::has_via_aes())
      {
      if(request.algo_name() == "AES")
         return new AES_Via;
      if(request.algo_name() == "AES-128")
         return new AES_Via_128;
      if(request.algo_name() == "AES-192")
         return new AES_Via_192;
      if(request.algo_name() == "AES-256")
         return new AES_Via_256;
      }
#endif

   return 0;
   }

}
