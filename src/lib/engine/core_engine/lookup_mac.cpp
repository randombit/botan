/*
* MAC Lookup
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/core_engine.h>
#include <botan/scan_name.h>
#include <botan/algo_factory.h>

#if defined(BOTAN_HAS_CBC_MAC)
  #include <botan/cbc_mac.h>
#endif

#if defined(BOTAN_HAS_CMAC)
  #include <botan/cmac.h>
#endif

#if defined(BOTAN_HAS_HMAC)
  #include <botan/hmac.h>
#endif

#if defined(BOTAN_HAS_POLY1305)
  #include <botan/poly1305.h>
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
  #include <botan/ssl3_mac.h>
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
  #include <botan/x919_mac.h>
#endif

namespace Botan {

/*
* Look for an algorithm with this name
*/
MessageAuthenticationCode*
Core_Engine::find_mac(const SCAN_Name& request,
                      Algorithm_Factory& af) const
   {
#if defined(BOTAN_HAS_HMAC)
   if(request.algo_name() == "HMAC" && request.arg_count() == 1)
      return new HMAC(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_CMAC)
   if(request.algo_name() == "CMAC" && request.arg_count() == 1)
      return new CMAC(af.make_block_cipher(request.arg(0)));
#endif

#if defined(BOTAN_HAS_POLY1305)
   if(request.algo_name() == "Poly1305")
      return new Poly1305;
#endif

#if defined(BOTAN_HAS_CBC_MAC)
   if(request.algo_name() == "CBC-MAC" && request.arg_count() == 1)
      return new CBC_MAC(af.make_block_cipher(request.arg(0)));
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
   if(request.algo_name() == "SSL3-MAC" && request.arg_count() == 1)
      return new SSL3_MAC(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   if(request.algo_name() == "X9.19-MAC" && request.arg_count() == 0)
      return new ANSI_X919_MAC(af.make_block_cipher("DES"));
#endif

   return nullptr;
   }

}
