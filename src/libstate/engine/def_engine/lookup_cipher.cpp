/*************************************************
* Cipher Lookup                                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <memory>

#if defined(BOTAN_HAS_AES)
  #include <botan/aes.h>
#endif

#if defined(BOTAN_HAS_BLOWFISH)
  #include <botan/blowfish.h>
#endif

#if defined(BOTAN_HAS_CAST)
  #include <botan/cast128.h>
  #include <botan/cast256.h>
#endif

#if defined(BOTAN_HAS_DES)
  #include <botan/des.h>
  #include <botan/desx.h>
#endif

#if defined(BOTAN_HAS_GOST)
  #include <botan/gost.h>
#endif

#if defined(BOTAN_HAS_IDEA)
  #include <botan/idea.h>
#endif

#if defined(BOTAN_HAS_KASUMI)
  #include <botan/kasumi.h>
#endif

#if defined(BOTAN_HAS_LION)
  #include <botan/lion.h>
#endif

#if defined(BOTAN_HAS_LUBY_RACKOFF)
  #include <botan/lubyrack.h>
#endif

#if defined(BOTAN_HAS_MARS)
  #include <botan/mars.h>
#endif

#if defined(BOTAN_HAS_MISTY1)
  #include <botan/misty1.h>
#endif

#if defined(BOTAN_HAS_NOEKEON)
  #include <botan/noekeon.h>
#endif

#if defined(BOTAN_HAS_RC2)
  #include <botan/rc2.h>
#endif

#if defined(BOTAN_HAS_RC5)
  #include <botan/rc5.h>
#endif

#if defined(BOTAN_HAS_RC6)
  #include <botan/rc6.h>
#endif

#if defined(BOTAN_HAS_SAFER)
  #include <botan/safer_sk.h>
#endif

#if defined(BOTAN_HAS_SEED)
  #include <botan/seed.h>
#endif

#if defined(BOTAN_HAS_SERPENT)
  #include <botan/serpent.h>
#endif

#if defined(BOTAN_HAS_SERPENT_IA32)
  #include <botan/serp_ia32.h>
#endif

#if defined(BOTAN_HAS_SKIPJACK)
  #include <botan/skipjack.h>
#endif

#if defined(BOTAN_HAS_SQUARE)
  #include <botan/square.h>
#endif

#if defined(BOTAN_HAS_TEA)
  #include <botan/tea.h>
#endif

#if defined(BOTAN_HAS_TWOFISH)
  #include <botan/twofish.h>
#endif

#if defined(BOTAN_HAS_XTEA)
  #include <botan/xtea.h>
#endif

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

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
  #include <botan/mode_pad.h>
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
BlockCipher*
Default_Engine::find_block_cipher(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return 0;
   const std::string algo_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_AES)
   HANDLE_TYPE_NO_ARGS("AES", AES);
   HANDLE_TYPE_NO_ARGS("AES-128", AES_128);
   HANDLE_TYPE_NO_ARGS("AES-192", AES_192);
   HANDLE_TYPE_NO_ARGS("AES-256", AES_256);
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   HANDLE_TYPE_NO_ARGS("Blowfish", Blowfish);
#endif

#if defined(BOTAN_HAS_CAST)
   HANDLE_TYPE_NO_ARGS("CAST-128", CAST_128);
   HANDLE_TYPE_NO_ARGS("CAST-256", CAST_256);
#endif

#if defined(BOTAN_HAS_DES)
   HANDLE_TYPE_NO_ARGS("DES", DES);
   HANDLE_TYPE_NO_ARGS("DESX", DESX);
   HANDLE_TYPE_NO_ARGS("TripleDES", TripleDES);
#endif

#if defined(BOTAN_HAS_GOST)
   HANDLE_TYPE_NO_ARGS("GOST", GOST);
#endif

#if defined(BOTAN_HAS_IDEA)
   HANDLE_TYPE_NO_ARGS("IDEA", IDEA);
#endif

#if defined(BOTAN_HAS_KASUMI)
   HANDLE_TYPE_NO_ARGS("KASUMI", KASUMI);
#endif

#if defined(BOTAN_HAS_MARS)
   HANDLE_TYPE_NO_ARGS("MARS", MARS);
#endif

#if defined(BOTAN_HAS_MISTY1)
   HANDLE_TYPE_ONE_U32BIT("MISTY1", MISTY1, 8);
#endif

#if defined(BOTAN_HAS_NOEKEON)
   HANDLE_TYPE_NO_ARGS("Noekeon", Noekeon);
#endif

#if defined(BOTAN_HAS_RC2)
   HANDLE_TYPE_NO_ARGS("RC2", RC2);
#endif

#if defined(BOTAN_HAS_RC5)
   HANDLE_TYPE_ONE_U32BIT("RC5", RC5, 12);
#endif

#if defined(BOTAN_HAS_RC6)
   HANDLE_TYPE_NO_ARGS("RC6", RC6);
#endif

#if defined(BOTAN_HAS_SAFER)
   HANDLE_TYPE_ONE_U32BIT("SAFER-SK", SAFER_SK, 10);
#endif

#if defined(BOTAN_HAS_SEED)
   HANDLE_TYPE_NO_ARGS("SEED", SEED);
#endif

#if defined(BOTAN_HAS_SERPENT_IA32)
   HANDLE_TYPE_NO_ARGS("Serpent", Serpent_IA32);
#elif defined(BOTAN_HAS_SERPENT)
   HANDLE_TYPE_NO_ARGS("Serpent", Serpent);
#endif

#if defined(BOTAN_HAS_SKIPJACK)
   HANDLE_TYPE_NO_ARGS("Skipjack", Skipjack);
#endif

#if defined(BOTAN_HAS_SQUARE)
   HANDLE_TYPE_NO_ARGS("Square", Square);
#endif

#if defined(BOTAN_HAS_TEA)
   HANDLE_TYPE_NO_ARGS("TEA", TEA);
#endif

#if defined(BOTAN_HAS_TWOFISH)
   HANDLE_TYPE_NO_ARGS("Twofish", Twofish);
#endif

#if defined(BOTAN_HAS_XTEA)
   HANDLE_TYPE_NO_ARGS("XTEA", XTEA);
#endif

#if defined(BOTAN_HAS_LUBY_RACKOFF)
   if(algo_name == "Luby-Rackoff" && name.size() >= 2)
      {
      HashFunction* hash = get_hash(name[1]);
      if(hash)
         return new LubyRackoff(hash);
      }
#endif

#if defined(BOTAN_HAS_LION)
   if(algo_name == "Lion")
      {
      if(name.size() != 4)
         throw Invalid_Algorithm_Name(algo_spec);

      std::auto_ptr<HashFunction> hash(get_hash(name[1]));
      if(!hash.get())
         throw Algorithm_Not_Found(name[1]);

      std::auto_ptr<StreamCipher> sc(get_stream_cipher(name[2]));
      if(!sc.get())
         throw Algorithm_Not_Found(name[2]);

      return new Lion(hash.release(), sc.release(), to_u32bit(name[3]));
      }
#endif

   return 0;
   }

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
StreamCipher*
Default_Engine::find_stream_cipher(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return 0;
   const std::string algo_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_ARC4)
   HANDLE_TYPE_ONE_U32BIT("ARC4", ARC4, 0);
   HANDLE_TYPE_ONE_U32BIT("RC4_drop", ARC4, 768);
#endif

#if defined(BOTAN_HAS_SALSA20)
   HANDLE_TYPE_NO_ARGS("Salsa20", Salsa20);
#endif

#if defined(BOTAN_HAS_TURING)
   HANDLE_TYPE_NO_ARGS("Turing", Turing);
#endif

#if defined(BOTAN_HAS_WID_WAKE)
   HANDLE_TYPE_NO_ARGS("WiderWake4+1-BE", WiderWake_41_BE);
#endif

   return 0;
   }

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
BlockCipherModePaddingMethod*
Default_Engine::find_bc_pad(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return 0;

   const std::string algo_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_CIPHER_MODE_PADDING)
   HANDLE_TYPE_NO_ARGS("PKCS7",       PKCS7_Padding);
   HANDLE_TYPE_NO_ARGS("OneAndZeros", OneAndZeros_Padding);
   HANDLE_TYPE_NO_ARGS("X9.23",       ANSI_X923_Padding);
   HANDLE_TYPE_NO_ARGS("NoPadding",   Null_Padding);
#endif

   return 0;
   }

}
