/*
* PBKDF Lookup
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/core_engine.h>
#include <botan/scan_name.h>
#include <botan/algo_factory.h>

#if defined(BOTAN_HAS_PBKDF1)
  #include <botan/pbkdf1.h>
#endif

#if defined(BOTAN_HAS_PBKDF2)
  #include <botan/pbkdf2.h>
#endif

#if defined(BOTAN_HAS_PGPS2K)
  #include <botan/pgp_s2k.h>
#endif

namespace Botan {

PBKDF* Core_Engine::find_pbkdf(const SCAN_Name& algo_spec,
                               Algorithm_Factory& af) const
   {
#if defined(BOTAN_HAS_PBKDF1)
   if(algo_spec.algo_name() == "PBKDF1" && algo_spec.arg_count() == 1)
      return new PKCS5_PBKDF1(af.make_hash_function(algo_spec.arg(0)));
#endif

#if defined(BOTAN_HAS_PBKDF2)
   if(algo_spec.algo_name() == "PBKDF2" && algo_spec.arg_count() == 1)
      {
      if(const MessageAuthenticationCode* mac_proto = af.prototype_mac(algo_spec.arg(0)))
         return new PKCS5_PBKDF2(mac_proto->clone());

      return new PKCS5_PBKDF2(af.make_mac("HMAC(" + algo_spec.arg(0) + ")"));
      }
#endif

#if defined(BOTAN_HAS_PGPS2K)
   if(algo_spec.algo_name() == "OpenPGP-S2K" && algo_spec.arg_count() == 1)
      return new OpenPGP_S2K(af.make_hash_function(algo_spec.arg(0)));
#endif

   return 0;
   }

}
