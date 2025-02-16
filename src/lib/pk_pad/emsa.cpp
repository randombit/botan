/*
* (C) 2015,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/emsa.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/pk_options.h>

#if defined(BOTAN_HAS_EMSA_X931)
   #include <botan/internal/emsa_x931.h>
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
   #include <botan/internal/emsa_pkcs1.h>
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   #include <botan/internal/pssr.h>
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
   #include <botan/internal/emsa_raw.h>
#endif

#if defined(BOTAN_HAS_ISO_9796)
   #include <botan/internal/iso9796.h>
#endif

namespace Botan {

std::unique_ptr<EMSA> EMSA::create_or_throw(PK_Signature_Options& options) {
   const auto hash = options.hash_function().optional();
   const auto padding = options.padding().optional();
   const bool is_raw_hash = !hash.has_value() || hash.value() == "Raw";
   const bool is_raw_padding = !padding.has_value() || padding.value() == "Raw";

   if(is_raw_padding) {
      // Only valid possibility for empty padding is no hash / "Raw" hash

#if defined(BOTAN_HAS_EMSA_RAW)
      if(is_raw_hash) {
         if(auto prehash = options.prehash().optional(); prehash.has_value() && prehash->has_value()) {
            if(auto prehash_fn = HashFunction::create(prehash->value())) {
               return std::make_unique<EMSA_Raw>(prehash_fn->output_length());
            }
         } else {
            return std::make_unique<EMSA_Raw>();
         }
      }
#endif
   } else {
      // null if raw_hash
      auto hash_fn = [&]() -> std::unique_ptr<HashFunction> {
         if(is_raw_hash) {
            return nullptr;
         } else {
            return HashFunction::create(hash.value());
         }
      }();

#if defined(BOTAN_HAS_EMSA_PKCS1)
      if(padding == "PKCS1v15") {
         if(is_raw_hash) {
            return std::make_unique<EMSA_PKCS1v15_Raw>(options.prehash().or_default(std::nullopt));
         } else if(hash_fn) {
            return std::make_unique<EMSA_PKCS1v15>(std::move(hash_fn));
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
      if(padding == "PSS_Raw" && hash_fn) {
         return std::make_unique<PSSR_Raw>(std::move(hash_fn), options.salt_size().optional());
      }

      if(padding == "PSS" && hash_fn) {
         return std::make_unique<PSSR>(std::move(hash_fn), options.salt_size().optional());
      }
#endif

#if defined(BOTAN_HAS_ISO_9796)
      if(padding == "ISO_9796_DS2" && hash_fn) {
         return std::make_unique<ISO_9796_DS2>(
            std::move(hash_fn), !options.using_explicit_trailer_field(), options.salt_size().optional());
      }

      //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
      if(padding == "ISO_9796_DS3" && hash_fn) {
         return std::make_unique<ISO_9796_DS3>(std::move(hash_fn), !options.using_explicit_trailer_field());
      }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
      if(padding == "X9.31" && hash_fn) {
         return std::make_unique<EMSA_X931>(std::move(hash_fn));
      }
#endif
   }

   throw Lookup_Error("Invalid or unavailable signature padding scheme\n" + options.to_string());
}

}  // namespace Botan
