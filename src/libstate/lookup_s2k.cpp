/*************************************************
* S2K Lookup                                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eng_def.h>
#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <memory>

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

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
S2K* Default_Engine::find_s2k(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return 0;

   const std::string algo_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_PBKDF1)
   if(algo_name == "PBKDF1")
      {
      if(name.size() == 2)
         return new PKCS5_PBKDF1(get_hash(name[1]));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

#if defined(BOTAN_HAS_PBKDF2)
   if(algo_name == "PBKDF2")
      {
      if(name.size() == 2)
         return new PKCS5_PBKDF2(get_mac("HMAC(" + name[1] + ")"));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

#if defined(BOTAN_HAS_PGPS2K)
   if(algo_name == "OpenPGP-S2K")
      {
      if(name.size() == 2)
         return new OpenPGP_S2K(get_hash(name[1]));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

   return 0;
   }

}
