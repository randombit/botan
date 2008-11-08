/*************************************************
* Hash Algorithms Lookup                         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/def_eng.h>
#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <memory>

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

#if defined(BOTAN_HAS_MD4_IA32)
  #include <botan/md4_ia32.h>
#endif

#if defined(BOTAN_HAS_MD5)
  #include <botan/md5.h>
#endif

#if defined(BOTAN_HAS_MD5_IA32)
  #include <botan/md5_ia32.h>
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

#if defined(BOTAN_HAS_SHA1_IA32)
  #include <botan/sha1_ia32.h>
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
  #include <botan/sha1_sse2.h>
#endif

#if defined(BOTAN_HAS_SHA1_AMD64)
  #include <botan/sha1_amd64.h>
#endif

#if defined(BOTAN_HAS_SHA2)
  #include <botan/sha2_32.h>
  #include <botan/sha2_64.h>
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

#if defined(BOTAN_HAS_MD4_IA32)
   HANDLE_TYPE_NO_ARGS("MD4", MD4_IA32);
#elif defined(BOTAN_HAS_MD4)
   HANDLE_TYPE_NO_ARGS("MD4", MD4);
#endif

#if defined(BOTAN_HAS_MD5_IA32)
   HANDLE_TYPE_NO_ARGS("MD5", MD5_IA32);
#elif defined(BOTAN_HAS_MD5)
   HANDLE_TYPE_NO_ARGS("MD5", MD5);
#endif

#if defined(BOTAN_HAS_RIPEMD_128)
   HANDLE_TYPE_NO_ARGS("RIPEMD-128", RIPEMD_128);
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
   HANDLE_TYPE_NO_ARGS("RIPEMD-160", RIPEMD_160);
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
   HANDLE_TYPE_NO_ARGS("SHA-160", SHA_160_SSE2);
#elif defined(BOTAN_HAS_SHA1_AMD64)
   HANDLE_TYPE_NO_ARGS("SHA-160", SHA_160_AMD64);
#elif defined(BOTAN_HAS_SHA1_IA32)
   HANDLE_TYPE_NO_ARGS("SHA-160", SHA_160_IA32);
#elif defined(BOTAN_HAS_SHA1)
   HANDLE_TYPE_NO_ARGS("SHA-160", SHA_160);
#endif

#if defined(BOTAN_HAS_SHA2)
   HANDLE_TYPE_NO_ARGS("SHA-224", SHA_224);
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

#if defined(BOTAN_HAS_PARALLEL_HASH)
   if(algo_name == "Parallel")
      {
      if(name.size() < 2)
         throw Invalid_Algorithm_Name(algo_spec);
      name.erase(name.begin());
      return new Parallel(name);
      }
#endif

   return 0;
   }

}
