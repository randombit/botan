/*
* Stream Cipher Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_ARC4)
  #include <botan/arc4.h>
#endif

#if defined(BOTAN_HAS_SALSA20)
  #include <botan/salsa20.h>
#endif

#if defined(BOTAN_HAS_TURING)
  #include <botan/turing.h>
#endif

#if defined(BOTAN_HAS_WID_WAKE)
  #include <botan/wid_wake.h>
#endif

namespace Botan {

/*
* Look for an algorithm with this name
*/
StreamCipher*
Core_Engine::find_stream_cipher(const SCAN_Name& request,
                                Algorithm_Factory&) const
   {
#if defined(BOTAN_HAS_ARC4)
   if(request.algo_name() == "ARC4")
      return new ARC4(request.arg_as_integer(0, 0));
   if(request.algo_name() == "RC4_drop")
      return new ARC4(768);
#endif

#if defined(BOTAN_HAS_SALSA20)
   if(request.algo_name() == "Salsa20")
      return new Salsa20;
#endif

#if defined(BOTAN_HAS_TURING)
   if(request.algo_name() == "Turing")
      return new Turing;
#endif

#if defined(BOTAN_HAS_WID_WAKE)
   if(request.algo_name() == "WiderWake4+1-BE")
      return new WiderWake_41_BE;
#endif

   return 0;
   }

}
