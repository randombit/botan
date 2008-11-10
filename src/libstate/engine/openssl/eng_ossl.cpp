/**
OpenSSL Engine
(C) 2008 Jack Lloyd
*/

#include <botan/eng_ossl.h>
#include <botan/arc4_openssl.h>
#include <botan/scan_name.h>

namespace Botan {

/**
* Look for an OpenSSL-suported stream cipher (ARC4)
*/
StreamCipher*
OpenSSL_Engine::find_stream_cipher(const std::string& algo_spec) const
   {
   SCAN_Name request(algo_spec);

   if(request.algo_name() == "ARC4")
      return new ARC4_OpenSSL(request.argument_as_u32bit(0, 0));
   if(request.algo_name() == "RC4_drop")
      return new ARC4_OpenSSL(768);

   return 0;
   }

}
