/*************************************************
* MAC Lookup                                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>

#if defined(BOTAN_HAS_CBC_MAC)
  #include <botan/cbc_mac.h>
#endif

#if defined(BOTAN_HAS_CMAC)
  #include <botan/cmac.h>
#endif

#if defined(BOTAN_HAS_HMAC)
  #include <botan/hmac.h>
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
  #include <botan/ssl3_mac.h>
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
  #include <botan/x919_mac.h>
#endif

namespace Botan {

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
MessageAuthenticationCode*
Default_Engine::find_mac(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return 0;
   const std::string algo_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_CBC_MAC)
   if(algo_name == "CBC-MAC")
      {
      if(name.size() == 2)
         return new CBC_MAC(get_block_cipher(name[1]));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

#if defined(BOTAN_HAS_CMAC)
   if(algo_name == "CMAC")
      {
      if(name.size() == 2)
         return new CMAC(get_block_cipher(name[1]));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

#if defined(BOTAN_HAS_HMAC)
   if(algo_name == "HMAC")
      {
      if(name.size() == 2)
         return new HMAC(get_hash(name[1]));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
   if(algo_name == "SSL3-MAC")
      {
      if(name.size() == 2)
         return new SSL3_MAC(get_hash(name[1]));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   if(algo_name == "X9.19-MAC")
      {
      if(name.size() == 1)
         return new ANSI_X919_MAC(get_block_cipher("DES"));
      throw Invalid_Algorithm_Name(algo_spec);
      }
#endif

   return 0;
   }

}
