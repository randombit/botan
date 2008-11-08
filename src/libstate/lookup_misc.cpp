/*************************************************
* MAC/PBKDF/Other Algorithms Lookup              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eng_def.h>
#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <memory>

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
* Some macros to simplify control flow           *
*************************************************/
#define HANDLE_TYPE_NO_ARGS(NAME, TYPE)        \
   if(algo_name == NAME)                       \
      {                                        \
      if(name.size() == 1)                     \
         return new TYPE;                      \
      throw Invalid_Algorithm_Name(algo_spec); \
      }

#define HANDLE_TYPE_ONE_U32BIT(NAME, TYPE, DEFAULT) \
   if(algo_name == NAME)                            \
      {                                             \
      if(name.size() == 1)                          \
         return new TYPE(DEFAULT);                  \
      if(name.size() == 2)                          \
         return new TYPE(to_u32bit(name[1]));       \
      throw Invalid_Algorithm_Name(algo_spec);      \
      }

#define HANDLE_TYPE_TWO_U32BIT(NAME, TYPE, DEFAULT)               \
   if(algo_name == NAME)                                          \
      {                                                           \
      if(name.size() == 1)                                        \
         return new TYPE(DEFAULT);                                \
      if(name.size() == 2)                                        \
         return new TYPE(to_u32bit(name[1]));                     \
      if(name.size() == 3)                                        \
         return new TYPE(to_u32bit(name[1]), to_u32bit(name[2])); \
      throw Invalid_Algorithm_Name(algo_spec);                    \
      }

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
