/*
* Stream Cipher Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/scan_name.h>
#include <botan/algo_factory.h>

#if defined(BOTAN_HAS_OFB)
  #include <botan/ofb.h>
#endif

#if defined(BOTAN_HAS_CTR_BE)
  #include <botan/ctr.h>
#endif

#if defined(BOTAN_HAS_RC4)
  #include <botan/rc4.h>
#endif

#if defined(BOTAN_HAS_CHACHA)
  #include <botan/chacha.h>
#endif

#if defined(BOTAN_HAS_SALSA20)
  #include <botan/salsa20.h>
#endif

namespace Botan {

/*
* Look for an algorithm with this name
*/
StreamCipher*
Core_Engine::find_stream_cipher(const SCAN_Name& request,
                                Algorithm_Factory& af) const
   {
#if defined(BOTAN_HAS_OFB)
   if(request.algo_name() == "OFB" && request.arg_count() == 1)
      {
      if(auto proto = af.prototype_block_cipher(request.arg(0)))
         return new OFB(proto->clone());
      }
#endif

#if defined(BOTAN_HAS_CTR_BE)
   if(request.algo_name() == "CTR-BE" && request.arg_count() == 1)
      {
      if(auto proto = af.prototype_block_cipher(request.arg(0)))
         return new CTR_BE(proto->clone());
      }
#endif

#if defined(BOTAN_HAS_RC4)
   if(request.algo_name() == "RC4")
      return new RC4(request.arg_as_integer(0, 0));
   if(request.algo_name() == "RC4_drop")
      return new RC4(768);
#endif

#if defined(BOTAN_HAS_CHACHA)
   if(request.algo_name() == "ChaCha")
      return new ChaCha;
#endif

#if defined(BOTAN_HAS_SALSA20)
   if(request.algo_name() == "Salsa20")
      return new Salsa20;
#endif

   return nullptr;
   }

}
