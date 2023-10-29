/*
* Hash Functions
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hash.h>

#include <botan/exceptn.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_ADLER32)
   #include <botan/internal/adler32.h>
#endif

#if defined(BOTAN_HAS_CRC24)
   #include <botan/internal/crc24.h>
#endif

#if defined(BOTAN_HAS_CRC32)
   #include <botan/internal/crc32.h>
#endif

#if defined(BOTAN_HAS_GOST_34_11)
   #include <botan/internal/gost_3411.h>
#endif

#if defined(BOTAN_HAS_KECCAK)
   #include <botan/internal/keccak.h>
#endif

#if defined(BOTAN_HAS_MD4)
   #include <botan/internal/md4.h>
#endif

#if defined(BOTAN_HAS_MD5)
   #include <botan/internal/md5.h>
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
   #include <botan/internal/rmd160.h>
#endif

#if defined(BOTAN_HAS_SHA1)
   #include <botan/internal/sha1.h>
#endif

#if defined(BOTAN_HAS_SHA2_32)
   #include <botan/internal/sha2_32.h>
#endif

#if defined(BOTAN_HAS_SHA2_64)
   #include <botan/internal/sha2_64.h>
#endif

#if defined(BOTAN_HAS_SHA3)
   #include <botan/internal/sha3.h>
#endif

#if defined(BOTAN_HAS_SHAKE)
   #include <botan/internal/shake.h>
#endif

#if defined(BOTAN_HAS_SKEIN_512)
   #include <botan/internal/skein_512.h>
#endif

#if defined(BOTAN_HAS_STREEBOG)
   #include <botan/internal/streebog.h>
#endif

#if defined(BOTAN_HAS_SM3)
   #include <botan/internal/sm3.h>
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
   #include <botan/internal/whirlpool.h>
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
   #include <botan/internal/par_hash.h>
#endif

#if defined(BOTAN_HAS_TRUNCATED_HASH)
   #include <botan/internal/trunc_hash.h>
#endif

#if defined(BOTAN_HAS_COMB4P)
   #include <botan/internal/comb4p.h>
#endif

#if defined(BOTAN_HAS_BLAKE2B)
   #include <botan/internal/blake2b.h>
#endif

#if defined(BOTAN_HAS_BLAKE2S)
   #include <botan/internal/blake2s.h>
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
   #include <botan/internal/commoncrypto.h>
#endif

namespace Botan {

std::unique_ptr<HashFunction> HashFunction::create(std::string_view algo_spec, std::string_view provider) {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto") {
      if(auto hash = make_commoncrypto_hash(algo_spec))
         return hash;

      if(!provider.empty())
         return nullptr;
   }
#endif

   if(provider.empty() == false && provider != "base") {
      return nullptr;  // unknown provider
   }

#if defined(BOTAN_HAS_SHA1)
   if(algo_spec == "SHA-1") {
      return std::make_unique<SHA_1>();
   }
#endif

#if defined(BOTAN_HAS_SHA2_32)
   if(algo_spec == "SHA-224") {
      return std::make_unique<SHA_224>();
   }

   if(algo_spec == "SHA-256") {
      return std::make_unique<SHA_256>();
   }
#endif

#if defined(BOTAN_HAS_SHA2_64)
   if(algo_spec == "SHA-384") {
      return std::make_unique<SHA_384>();
   }

   if(algo_spec == "SHA-512") {
      return std::make_unique<SHA_512>();
   }

   if(algo_spec == "SHA-512-256") {
      return std::make_unique<SHA_512_256>();
   }
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
   if(algo_spec == "RIPEMD-160") {
      return std::make_unique<RIPEMD_160>();
   }
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
   if(algo_spec == "Whirlpool") {
      return std::make_unique<Whirlpool>();
   }
#endif

#if defined(BOTAN_HAS_MD5)
   if(algo_spec == "MD5") {
      return std::make_unique<MD5>();
   }
#endif

#if defined(BOTAN_HAS_MD4)
   if(algo_spec == "MD4") {
      return std::make_unique<MD4>();
   }
#endif

#if defined(BOTAN_HAS_GOST_34_11)
   if(algo_spec == "GOST-R-34.11-94" || algo_spec == "GOST-34.11") {
      return std::make_unique<GOST_34_11>();
   }
#endif

#if defined(BOTAN_HAS_ADLER32)
   if(algo_spec == "Adler32") {
      return std::make_unique<Adler32>();
   }
#endif

#if defined(BOTAN_HAS_CRC24)
   if(algo_spec == "CRC24") {
      return std::make_unique<CRC24>();
   }
#endif

#if defined(BOTAN_HAS_CRC32)
   if(algo_spec == "CRC32") {
      return std::make_unique<CRC32>();
   }
#endif

#if defined(BOTAN_HAS_STREEBOG)
   if(algo_spec == "Streebog-256") {
      return std::make_unique<Streebog>(256);
   }
   if(algo_spec == "Streebog-512") {
      return std::make_unique<Streebog>(512);
   }
#endif

#if defined(BOTAN_HAS_SM3)
   if(algo_spec == "SM3") {
      return std::make_unique<SM3>();
   }
#endif

   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_SKEIN_512)
   if(req.algo_name() == "Skein-512") {
      return std::make_unique<Skein_512>(req.arg_as_integer(0, 512), req.arg(1, ""));
   }
#endif

#if defined(BOTAN_HAS_BLAKE2B)
   if(req.algo_name() == "Blake2b" || req.algo_name() == "BLAKE2b") {
      return std::make_unique<BLAKE2b>(req.arg_as_integer(0, 512));
   }
#endif

#if defined(BOTAN_HAS_BLAKE2S)
   if(req.algo_name() == "Blake2s" || req.algo_name() == "BLAKE2s") {
      return std::make_unique<BLAKE2s>(req.arg_as_integer(0, 256));
   }
#endif

#if defined(BOTAN_HAS_KECCAK)
   if(req.algo_name() == "Keccak-1600") {
      return std::make_unique<Keccak_1600>(req.arg_as_integer(0, 512));
   }
#endif

#if defined(BOTAN_HAS_SHA3)
   if(req.algo_name() == "SHA-3") {
      return std::make_unique<SHA_3>(req.arg_as_integer(0, 512));
   }
#endif

#if defined(BOTAN_HAS_SHAKE)
   if(req.algo_name() == "SHAKE-128" && req.arg_count() == 1) {
      return std::make_unique<SHAKE_128>(req.arg_as_integer(0));
   }
   if(req.algo_name() == "SHAKE-256" && req.arg_count() == 1) {
      return std::make_unique<SHAKE_256>(req.arg_as_integer(0));
   }
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
   if(req.algo_name() == "Parallel") {
      std::vector<std::unique_ptr<HashFunction>> hashes;

      for(size_t i = 0; i != req.arg_count(); ++i) {
         auto h = HashFunction::create(req.arg(i));
         if(!h) {
            return nullptr;
         }
         hashes.push_back(std::move(h));
      }

      return std::make_unique<Parallel>(hashes);
   }
#endif

#if defined(BOTAN_HAS_TRUNCATED_HASH)
   if(req.algo_name() == "Truncated" && req.arg_count() == 2) {
      auto hash = HashFunction::create(req.arg(0));
      if(!hash) {
         return nullptr;
      }

      return std::make_unique<Truncated_Hash>(std::move(hash), req.arg_as_integer(1));
   }
#endif

#if defined(BOTAN_HAS_COMB4P)
   if(req.algo_name() == "Comb4P" && req.arg_count() == 2) {
      auto h1 = HashFunction::create(req.arg(0));
      auto h2 = HashFunction::create(req.arg(1));

      if(h1 && h2) {
         return std::make_unique<Comb4P>(std::move(h1), std::move(h2));
      }
   }
#endif

   return nullptr;
}

//static
std::unique_ptr<HashFunction> HashFunction::create_or_throw(std::string_view algo, std::string_view provider) {
   if(auto hash = HashFunction::create(algo, provider)) {
      return hash;
   }
   throw Lookup_Error("Hash", algo, provider);
}

std::vector<std::string> HashFunction::providers(std::string_view algo_spec) {
   return probe_providers_of<HashFunction>(algo_spec, {"base", "commoncrypto"});
}

}  // namespace Botan
