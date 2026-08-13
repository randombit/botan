/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hash_engine_sha2_32.h>

#include <botan/assert.h>
#include <botan/internal/hash_engine_mdx.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/sha2_32.h>

#if defined(BOTAN_HAS_HASH_ENGINE_SHA2_32_AVX2) || defined(BOTAN_HAS_HASH_ENGINE_SHA2_32_AVX512)
   #define BOTAN_HASH_ENGINE_SHA2_32_HAS_IMPL
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

std::unique_ptr<Hash_Engine> create_sha2_32_mb_engine(std::string_view hash_fn,
                                                      std::span<const uint8_t> common_prefix,
                                                      std::string_view provider) {
#if defined(BOTAN_HASH_ENGINE_SHA2_32_HAS_IMPL)
   size_t output_length = 0;

   const SCAN_Name req(hash_fn);
   if(req.algo_name() == "SHA-256" && req.arg_count() == 0) {
      output_length = 32;
   } else if(req.algo_name() == "Truncated" && req.arg_count() == 2 && req.arg(0) == "SHA-256") {
      const size_t bits = req.arg_as_integer(1);
      if(bits == 0 || bits % 8 != 0 || bits > 256) {
         return nullptr;
      }
      output_length = bits / 8;
   } else {
      return nullptr;
   }

   SHA_256::digest_type midstate;
   SHA_256::init(midstate);
   const size_t full_bytes = common_prefix.size() - common_prefix.size() % SHA_256::block_bytes;
   if(full_bytes > 0) {
      SHA_256::compress_digest(midstate, common_prefix.first(full_bytes), full_bytes / SHA_256::block_bytes);
   }

   auto make_engine = [&](std::string_view feat,
                          size_t lanes,
                          MDx_MB_Engine<uint32_t>::compress_fn compress,
                          MDx_MB_Engine<uint32_t>::extract_fn extract) {
      return std::make_unique<MDx_MB_Engine<uint32_t>>(hash_fn,
                                                       output_length,
                                                       common_prefix,
                                                       feat,
                                                       lanes,
                                                       SHA_256::block_bytes,
                                                       SHA_256::ctr_bytes,
                                                       midstate,
                                                       compress,
                                                       extract);
   };

   #if defined(BOTAN_HAS_HASH_ENGINE_SHA2_32_AVX512)
   if(auto feat = CPUID::check(CPUID::Feature::AVX512)) {
      if(provider.empty() || provider == *feat) {
         return make_engine(*feat, 16, sha2_32_mb_compress_x16, sha2_32_mb_extract_x16);
      }
   }
   #endif

   #if defined(BOTAN_HAS_HASH_ENGINE_SHA2_32_AVX2)
   if(auto feat = CPUID::check(CPUID::Feature::AVX2)) {
      if(provider.empty() || provider == *feat) {
         return make_engine(*feat, 8, sha2_32_mb_compress_x8, sha2_32_mb_extract_x8);
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
