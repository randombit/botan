/*************************************************
* Default Engine Algorithms Source File          *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/eng_def.h>
#include <botan/lookup.h>
#include <botan/parsing.h>

#include <botan/aes.h>

#include <botan/des.h>

#include <botan/adler32.h>
#include <botan/crc24.h>
#include <botan/crc32.h>

#include <botan/rmd160.h>
#include <botan/sha160.h>
#include <botan/sha256.h>
#include <botan/sha_64.h>

#include <botan/par_hash.h>

#include <botan/cbc_mac.h>
#include <botan/cmac.h>
#include <botan/hmac.h>
#include <botan/x919_mac.h>

#include <botan/mode_pad.h>

#include <botan/pkcs5.h>

namespace Botan {

/*************************************************
* Some macros to simplify control flow           *
*************************************************/
#define HANDLE_TYPE_NO_ARGS_BC(NAME, TYPE)                    \
   if(algo_name == NAME)                                      \
      {                                                       \
      if(name.size() == 1)                                    \
         return std::tr1::shared_ptr<BlockCipher>(new TYPE);  \
      throw Invalid_Algorithm_Name(algo_spec);                \
      }

#define HANDLE_TYPE_NO_ARGS_SC(NAME, TYPE)                    \
   if(algo_name == NAME)                                      \
      {                                                       \
      if(name.size() == 1)                                    \
         return std::tr1::shared_ptr<StreamCipher>(new TYPE); \
      throw Invalid_Algorithm_Name(algo_spec);                \
      }

#define HANDLE_TYPE_NO_ARGS_HF(NAME, TYPE)                    \
   if(algo_name == NAME)                                      \
      {                                                       \
      if(name.size() == 1)                                    \
         return std::tr1::shared_ptr<HashFunction>(new TYPE); \
      throw Invalid_Algorithm_Name(algo_spec);                \
      }

#define HANDLE_TYPE_NO_ARGS_MAC(NAME, TYPE)                                 \
   if(algo_name == NAME)                                                    \
      {                                                                     \
      if(name.size() == 1)                                                  \
         return std::tr1::shared_ptr<MessageAuthenticationCode>(new TYPE);  \
      throw Invalid_Algorithm_Name(algo_spec);                              \
      }

#define HANDLE_TYPE_NO_ARGS_S2K(NAME, TYPE)                                 \
   if(algo_name == NAME)                                                    \
      {                                                                     \
      if(name.size() == 1)                                                  \
         return std::tr1::shared_ptr<S2K>(new TYPE);                        \
      throw Invalid_Algorithm_Name(algo_spec);                              \
      }

#define HANDLE_TYPE_NO_ARGS_PM(NAME, TYPE)                                    \
   if(algo_name == NAME)                                                      \
      {                                                                       \
      if(name.size() == 1)                                                    \
         return std::tr1::shared_ptr<BlockCipherModePaddingMethod>(new TYPE); \
      throw Invalid_Algorithm_Name(algo_spec);                                \
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



#define HANDLE_TYPE_ONE_STRING_MAC(NAME, TYPE)                                       \
   if(algo_name == NAME)                                                             \
      {                                                                              \
      if(name.size() == 2)                                                           \
         return std::tr1::shared_ptr<MessageAuthenticationCode>(new TYPE(name[1]));  \
      throw Invalid_Algorithm_Name(algo_spec);                                       \
      }

#define HANDLE_TYPE_ONE_STRING_S2K(NAME, TYPE)                 \
   if(algo_name == NAME)                                       \
      {                                                        \
      if(name.size() == 2)                                     \
         return std::tr1::shared_ptr<S2K>(new TYPE(name[1]));  \
      throw Invalid_Algorithm_Name(algo_spec); \
      }


/*************************************************
* Look for an algorithm with this name           *
*************************************************/
std::tr1::shared_ptr<BlockCipher>
Default_Engine::find_block_cipher(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return std::tr1::shared_ptr<BlockCipher>();
   const std::string algo_name = deref_alias(name[0]);

   HANDLE_TYPE_NO_ARGS_BC("AES", AES);
   HANDLE_TYPE_NO_ARGS_BC("AES-128", AES_128);
   HANDLE_TYPE_NO_ARGS_BC("AES-192", AES_192);
   HANDLE_TYPE_NO_ARGS_BC("AES-256", AES_256);

   HANDLE_TYPE_NO_ARGS_BC("DES", DES);
   HANDLE_TYPE_NO_ARGS_BC("DESX", DESX);
   HANDLE_TYPE_NO_ARGS_BC("TripleDES", TripleDES);

   return std::tr1::shared_ptr<BlockCipher>();
   }

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
std::tr1::shared_ptr<StreamCipher>
Default_Engine::find_stream_cipher(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return std::tr1::shared_ptr<StreamCipher>();
   const std::string algo_name = deref_alias(name[0]);

   return std::tr1::shared_ptr<StreamCipher>();
   }

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
std::tr1::shared_ptr<HashFunction>
Default_Engine::find_hash(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return std::tr1::shared_ptr<HashFunction>();
   const std::string algo_name = deref_alias(name[0]);

   HANDLE_TYPE_NO_ARGS_HF("Adler32", Adler32);
   HANDLE_TYPE_NO_ARGS_HF("CRC24", CRC24);
   HANDLE_TYPE_NO_ARGS_HF("CRC32", CRC32);

   HANDLE_TYPE_NO_ARGS_HF("RIPEMD-160", RIPEMD_160);

   HANDLE_TYPE_NO_ARGS_HF("SHA-160", SHA_160);
   HANDLE_TYPE_NO_ARGS_HF("SHA-224", SHA_224);
   HANDLE_TYPE_NO_ARGS_HF("SHA-256", SHA_256);
   HANDLE_TYPE_NO_ARGS_HF("SHA-384", SHA_384);
   HANDLE_TYPE_NO_ARGS_HF("SHA-512", SHA_512);


   if(algo_name == "Parallel")
      {
      if(name.size() < 2)
         throw Invalid_Algorithm_Name(algo_spec);
      name.erase(name.begin());
      return std::tr1::shared_ptr<HashFunction>(new Parallel(name));
      }
   return std::tr1::shared_ptr<HashFunction>();
   }

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
std::tr1::shared_ptr<MessageAuthenticationCode>
Default_Engine::find_mac(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return std::tr1::shared_ptr<MessageAuthenticationCode>();
   const std::string algo_name = deref_alias(name[0]);

   HANDLE_TYPE_ONE_STRING_MAC("CBC-MAC", CBC_MAC);
   HANDLE_TYPE_ONE_STRING_MAC("CMAC", CMAC);
   HANDLE_TYPE_ONE_STRING_MAC("HMAC", HMAC);
   HANDLE_TYPE_NO_ARGS_MAC("X9.19-MAC", ANSI_X919_MAC);

   return std::tr1::shared_ptr<MessageAuthenticationCode>();
   }

/*************************************************
* Look for an algorithm with this name           *
*************************************************/

std::tr1::shared_ptr<S2K>
Default_Engine::find_s2k(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return std::tr1::shared_ptr<S2K>();

   const std::string algo_name = deref_alias(name[0]);

   HANDLE_TYPE_ONE_STRING_S2K("PBKDF1", PKCS5_PBKDF1);
   HANDLE_TYPE_ONE_STRING_S2K("PBKDF2", PKCS5_PBKDF2);


   return std::tr1::shared_ptr<S2K>();
   }
/*************************************************
* Look for an algorithm with this name           *
*************************************************/
std::tr1::shared_ptr<BlockCipherModePaddingMethod>
Default_Engine::find_bc_pad(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.empty())
      return std::tr1::shared_ptr<BlockCipherModePaddingMethod>();

   const std::string algo_name = deref_alias(name[0]);

   HANDLE_TYPE_NO_ARGS_PM("PKCS7",       PKCS7_Padding);
   HANDLE_TYPE_NO_ARGS_PM("OneAndZeros", OneAndZeros_Padding);
   HANDLE_TYPE_NO_ARGS_PM("X9.23",       ANSI_X923_Padding);
   HANDLE_TYPE_NO_ARGS_PM("NoPadding",   Null_Padding);

   return std::tr1::shared_ptr<BlockCipherModePaddingMethod>();
   }

}
