/*
* Hash Functions
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hash.h>
#include <botan/cpuid.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_ADLER32)
  #include <botan/adler32.h>
#endif

#if defined(BOTAN_HAS_CRC24)
  #include <botan/crc24.h>
#endif

#if defined(BOTAN_HAS_CRC32)
  #include <botan/crc32.h>
#endif

#if defined(BOTAN_HAS_GOST_34_11)
  #include <botan/gost_3411.h>
#endif

#if defined(BOTAN_HAS_KECCAK)
  #include <botan/keccak.h>
#endif

#if defined(BOTAN_HAS_MD4)
  #include <botan/md4.h>
#endif

#if defined(BOTAN_HAS_MD5)
  #include <botan/md5.h>
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
  #include <botan/rmd160.h>
#endif

#if defined(BOTAN_HAS_SHA1)
  #include <botan/sha160.h>
#endif

#if defined(BOTAN_HAS_SHA2_32)
  #include <botan/sha2_32.h>
#endif

#if defined(BOTAN_HAS_SHA2_64)
  #include <botan/sha2_64.h>
#endif

#if defined(BOTAN_HAS_SKEIN_512)
  #include <botan/skein_512.h>
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

#if defined(BOTAN_HAS_COMB4P)
  #include <botan/comb4p.h>
#endif

#if defined(BOTAN_HAS_BLAKE2B)
  #include <botan/blake2b.h>
#endif

namespace Botan {

std::unique_ptr<HashFunction> HashFunction::create(const std::string& algo_spec,
                                                   const std::string& provider)
   {
   return std::unique_ptr<HashFunction>(make_a<HashFunction>(Botan::HashFunction::Spec(algo_spec), provider));
   }

std::vector<std::string> HashFunction::providers(const std::string& algo_spec)
   {
   return providers_of<HashFunction>(HashFunction::Spec(algo_spec));
   }

HashFunction::HashFunction() {}

HashFunction::~HashFunction() {}

#define BOTAN_REGISTER_HASH(name, maker) BOTAN_REGISTER_T(HashFunction, name, maker)
#define BOTAN_REGISTER_HASH_NOARGS(name) BOTAN_REGISTER_T_NOARGS(HashFunction, name)

#define BOTAN_REGISTER_HASH_1LEN(name, def) BOTAN_REGISTER_T_1LEN(HashFunction, name, def)

#define BOTAN_REGISTER_HASH_NAMED_NOARGS(type, name) \
   BOTAN_REGISTER_NAMED_T(HashFunction, name, type, make_new_T<type>)
#define BOTAN_REGISTER_HASH_NAMED_1LEN(type, name, def) \
   BOTAN_REGISTER_NAMED_T(HashFunction, name, type, (make_new_T_1len<type,def>))

#define BOTAN_REGISTER_HASH_NOARGS_IF(cond, type, name, provider, pref)      \
   BOTAN_COND_REGISTER_NAMED_T_NOARGS(cond, HashFunction, type, name, provider, pref)

#if defined(BOTAN_HAS_ADLER32)
BOTAN_REGISTER_HASH_NOARGS(Adler32);
#endif

#if defined(BOTAN_HAS_CRC24)
BOTAN_REGISTER_HASH_NOARGS(CRC24);
#endif

#if defined(BOTAN_HAS_CRC32)
BOTAN_REGISTER_HASH_NOARGS(CRC32);
#endif

#if defined(BOTAN_HAS_COMB4P)
BOTAN_REGISTER_NAMED_T(HashFunction, "Comb4P", Comb4P, Comb4P::make);
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
BOTAN_REGISTER_NAMED_T(HashFunction, "Parallel", Parallel, Parallel::make);
#endif

#if defined(BOTAN_HAS_GOST_34_11)
BOTAN_REGISTER_HASH_NAMED_NOARGS(GOST_34_11, "GOST-R-34.11-94");
#endif

#if defined(BOTAN_HAS_KECCAK)
BOTAN_REGISTER_HASH_NAMED_1LEN(Keccak_1600, "Keccak-1600", 512);
#endif

#if defined(BOTAN_HAS_MD4)
BOTAN_REGISTER_HASH_NOARGS(MD4);
#endif

#if defined(BOTAN_HAS_MD5)
BOTAN_REGISTER_HASH_NOARGS(MD5);
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
BOTAN_REGISTER_HASH_NAMED_NOARGS(RIPEMD_160, "RIPEMD-160");
#endif

#if defined(BOTAN_HAS_SHA1)
BOTAN_REGISTER_HASH_NAMED_NOARGS(SHA_160, "SHA-160");
#endif

#if defined(BOTAN_HAS_SHA2_32)
BOTAN_REGISTER_HASH_NAMED_NOARGS(SHA_224, "SHA-224");
BOTAN_REGISTER_HASH_NAMED_NOARGS(SHA_256, "SHA-256");
#endif

#if defined(BOTAN_HAS_SHA2_64)
BOTAN_REGISTER_HASH_NAMED_NOARGS(SHA_384, "SHA-384");
BOTAN_REGISTER_HASH_NAMED_NOARGS(SHA_512, "SHA-512");
BOTAN_REGISTER_HASH_NAMED_NOARGS(SHA_512_256, "SHA-512-256");
#endif

#if defined(BOTAN_HAS_TIGER)
BOTAN_REGISTER_NAMED_T_2LEN(HashFunction, Tiger, "Tiger", "base", 24, 3);
#endif

#if defined(BOTAN_HAS_SKEIN_512)
BOTAN_REGISTER_NAMED_T(HashFunction, "Skein-512", Skein_512, Skein_512::make);
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
BOTAN_REGISTER_HASH_NOARGS(Whirlpool);
#endif

#if defined(BOTAN_HAS_BLAKE2B)
BOTAN_REGISTER_NAMED_T(HashFunction, "Blake2b", Blake2b, Blake2b::make);
#endif

}
