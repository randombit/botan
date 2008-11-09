/*************************************************
* S2K Lookup                                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
#include <botan/lookup.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_PBKDF1)
  #include <botan/pbkdf1.h>
#endif

#if defined(BOTAN_HAS_PBKDF2)
  #include <botan/pbkdf2.h>
  #include <botan/hmac.h>
#endif

#if defined(BOTAN_HAS_PGPS2K)
  #include <botan/pgp_s2k.h>
#endif

namespace Botan {

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
S2K* Default_Engine::find_s2k(const std::string& algo_spec) const
   {
   SCAN_Name request(algo_spec);

#if defined(BOTAN_HAS_PBKDF1)
   if(request.algo_name() == "PBKDF1" && request.arg_count() == 1)
      return new PKCS5_PBKDF1(get_hash(request.argument(0)));
#endif

#if defined(BOTAN_HAS_PBKDF2)
   if(request.algo_name() == "PBKDF2" && request.arg_count() == 1)
      return new PKCS5_PBKDF2(new HMAC(get_hash(request.argument(0))));
#endif

#if defined(BOTAN_HAS_PGPS2K)
   if(request.algo_name() == "OpenPGP-S2K" && request.arg_count() == 1)
      return new OpenPGP_S2K(get_hash(request.argument(0)));
#endif

   return 0;
   }

}
