/*************************************************
* Stream Cipher Lookup                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
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

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
StreamCipher*
Default_Engine::find_stream_cipher(const std::string& algo_spec) const
   {
   SCAN_Name request(algo_spec);

#if defined(BOTAN_HAS_ARC4)
   if(request.algo_name() == "ARC4")
      return new ARC4(request.argument_as_u32bit(0, 0));
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
