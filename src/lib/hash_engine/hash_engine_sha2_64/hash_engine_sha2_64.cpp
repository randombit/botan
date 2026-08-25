/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_64.h>

#include <botan/assert.h>
#include <botan/internal/hash_engine_mdx.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/sha2_64.h>

#if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_AVX2) || defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_AVX512) || \
   defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_ARMV8)
   #define BOTAN_HASH_ENGINE_SHA2_64_HAS_IMPL
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

std::unique_ptr<Hash_Engine> create_sha2_64_mb_engine(std::string_view hash_fn,
                                                      std::span<const uint8_t> common_prefix,
                                                      std::string_view provider) {
#if defined(BOTAN_HASH_ENGINE_SHA2_64_HAS_IMPL)
   size_t output_length = 0;
   SHA_512::digest_type midstate;

   const SCAN_Name req(hash_fn);
   if(req.algo_name() == "SHA-512" && req.arg_count() == 0) {
      output_length = SHA_512::output_bytes;
      SHA_512::init(midstate);
   } else if(req.algo_name() == "SHA-384" && req.arg_count() == 0) {
      output_length = SHA_384::output_bytes;
      SHA_384::init(midstate);
   } else if(req.algo_name() == "SHA-512-256" && req.arg_count() == 0) {
      output_length = SHA_512_256::output_bytes;
      SHA_512_256::init(midstate);
   } else if(req.algo_name() == "Truncated" && req.arg_count() == 2 && req.arg(0) == "SHA-512") {
      const size_t bits = req.arg_as_integer(1);
      if(bits == 0 || bits % 8 != 0 || bits > 512) {
         return nullptr;
      }
      output_length = bits / 8;
      SHA_512::init(midstate);
   } else {
      return nullptr;
   }

   const size_t full_bytes = common_prefix.size() - common_prefix.size() % SHA_512::block_bytes;
   if(full_bytes > 0) {
      SHA_512::compress_digest(midstate, common_prefix.first(full_bytes), full_bytes / SHA_512::block_bytes);
   }

   auto make_engine = [&](std::string_view feat,
                          size_t lanes,
                          MDx_MB_Engine<uint64_t>::compress_fn compress,
                          MDx_MB_Engine<uint64_t>::extract_fn extract) {
      return std::make_unique<MDx_MB_Engine<uint64_t>>(hash_fn,
                                                       output_length,
                                                       common_prefix,
                                                       feat,
                                                       lanes,
                                                       SHA_512::block_bytes,
                                                       SHA_512::ctr_bytes,
                                                       midstate,
                                                       compress,
                                                       extract);
   };

   #if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SHA2_512)) {
      if(provider.empty() || provider == *feat) {
         return make_engine(*feat, SHA2_64_ARMV8_STREAMS, sha2_64_mb_compress_armv8, sha2_64_mb_extract_armv8);
      }
   }
   #endif

   #if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512)) {
      if(provider.empty() || provider == *feat) {
         return make_engine(*feat, 8, sha2_64_mb_compress_x8, sha2_64_mb_extract_x8);
      }
   }
   #endif

   #if defined(BOTAN_HAS_HASH_ENGINE_SHA2_64_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2)) {
      if(provider.empty() || provider == *feat) {
         return make_engine(*feat, 4, sha2_64_mb_compress_x4, sha2_64_mb_extract_x4);
      }
   }
   #endif

   return nullptr;
#else
   BOTAN_UNUSED(hash_fn, common_prefix, provider);
   return nullptr;
#endif
}

}  // namespace Botan
