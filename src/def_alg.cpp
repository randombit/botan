/*************************************************
* Default Engine Algorithms Source File          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eng_def.h>
#include <botan/libstate.h>
#include <botan/parsing.h>

#include <botan/mode_pad.h>

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

#if defined(BOTAN_HAS_ADLER32)
  #include <botan/adler32.h>
#endif

#if defined(BOTAN_HAS_CRC24)
  #include <botan/crc24.h>
#endif

#if defined(BOTAN_HAS_CRC32)
  #include <botan/crc32.h>
#endif

#if defined(BOTAN_HAS_FORK_256)
  #include <botan/fork256.h>
#endif

#if defined(BOTAN_HAS_HAS_160)
  #include <botan/has160.h>
#endif

#if defined(BOTAN_HAS_MD2)
  #include <botan/md2.h>
#endif

#if defined(BOTAN_HAS_MD4)
  #include <botan/md4.h>
#endif

#if defined(BOTAN_HAS_MD5)
  #include <botan/md5.h>
#endif

#if defined(BOTAN_HAS_RIPEMD_128)
  #include <botan/rmd128.h>
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
  #include <botan/rmd160.h>
#endif

#if defined(BOTAN_HAS_SHA1)
  #include <botan/sha160.h>
#endif

#if defined(BOTAN_HAS_SHA2)
  #include <botan/sha256.h>
  #include <botan/sha_64.h>
#endif

#if defined(BOTAN_HAS_TIGER)
  #include <botan/tiger.h>
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
  #include <botan/whrlpool.h>
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
  #include <botan/par_hash.h>
#endif

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

#define HANDLE_TYPE_ONE_STRING(NAME, TYPE)     \
   if(algo_name == NAME)                       \
      {                                        \
      if(name.size() == 2)                     \
         return new TYPE(name[1]);             \
      throw Invalid_Algorithm_Name(algo_spec); \
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

#if defined(BOTAN_HAS_SERPENT)
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
      HashFunction* hash = find_hash(name[1]);
      if(hash)
         return new LubyRackoff(hash);
      }
#endif

#if defined(BOTAN_HAS_LION)
   if(algo_name == "Lion")
      {
      if(name.size() != 4)
         throw Invalid_Algorithm_Name(algo_spec);
      return new Lion(name[1], name[2], to_u32bit(name[3]));
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
HashFunction*
Default_Engine::find_hash(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return 0;
   const std::string algo_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_ADLER32)
   HANDLE_TYPE_NO_ARGS("Adler32", Adler32);
#endif

#if defined(BOTAN_HAS_CRC24)
   HANDLE_TYPE_NO_ARGS("CRC24", CRC24);
#endif

#if defined(BOTAN_HAS_CRC32)
   HANDLE_TYPE_NO_ARGS("CRC32", CRC32);
#endif

#if defined(BOTAN_HAS_FORK_256)
   HANDLE_TYPE_NO_ARGS("FORK-256", FORK_256);
#endif

#if defined(BOTAN_HAS_HAS_160)
   HANDLE_TYPE_NO_ARGS("HAS-160", HAS_160);
#endif

#if defined(BOTAN_HAS_MD2)
   HANDLE_TYPE_NO_ARGS("MD2", MD2);
#endif

#if defined(BOTAN_HAS_MD4)
   HANDLE_TYPE_NO_ARGS("MD4", MD4);
#endif

#if defined(BOTAN_HAS_MD5)
   HANDLE_TYPE_NO_ARGS("MD5", MD5);
#endif

#if defined(BOTAN_HAS_RIPEMD_128)
   HANDLE_TYPE_NO_ARGS("RIPEMD-128", RIPEMD_128);
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
   HANDLE_TYPE_NO_ARGS("RIPEMD-160", RIPEMD_160);
#endif

#if defined(BOTAN_HAS_SHA1)
   HANDLE_TYPE_NO_ARGS("SHA-160", SHA_160);
#endif

#if defined(BOTAN_HAS_SHA2)
   HANDLE_TYPE_NO_ARGS("SHA-256", SHA_256);
   HANDLE_TYPE_NO_ARGS("SHA-384", SHA_384);
   HANDLE_TYPE_NO_ARGS("SHA-512", SHA_512);
#endif

#if defined(BOTAN_HAS_TIGER)
   HANDLE_TYPE_TWO_U32BIT("Tiger", Tiger, 24);
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
   HANDLE_TYPE_NO_ARGS("Whirlpool", Whirlpool);
#endif

   if(algo_name == "Parallel")
      {
      if(name.size() < 2)
         throw Invalid_Algorithm_Name(algo_spec);
      name.erase(name.begin());
      return new Parallel(name);
      }

   return 0;
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
   HANDLE_TYPE_ONE_STRING("CBC-MAC", CBC_MAC);
#endif

#if defined(BOTAN_HAS_CMAC)
   HANDLE_TYPE_ONE_STRING("CMAC", CMAC);
#endif

#if defined(BOTAN_HAS_HMAC)
   HANDLE_TYPE_ONE_STRING("HMAC", HMAC);
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
   HANDLE_TYPE_ONE_STRING("SSL3-MAC", SSL3_MAC);
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
   HANDLE_TYPE_NO_ARGS("X9.19-MAC", ANSI_X919_MAC);
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
   HANDLE_TYPE_ONE_STRING("PBKDF1", PKCS5_PBKDF1);
#endif

#if defined(BOTAN_HAS_PBKDF2)
   HANDLE_TYPE_ONE_STRING("PBKDF2", PKCS5_PBKDF2);
#endif

#if defined(BOTAN_HAS_PGPS2K)
   HANDLE_TYPE_ONE_STRING("OpenPGP-S2K", OpenPGP_S2K);
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

   HANDLE_TYPE_NO_ARGS("PKCS7",       PKCS7_Padding);
   HANDLE_TYPE_NO_ARGS("OneAndZeros", OneAndZeros_Padding);
   HANDLE_TYPE_NO_ARGS("X9.23",       ANSI_X923_Padding);
   HANDLE_TYPE_NO_ARGS("NoPadding",   Null_Padding);

   return 0;
   }

}
