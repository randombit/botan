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

std::unique_ptr<EMSA> EMSA::create_or_throw(const PK_Signature_Options& options) {
   const bool is_raw_hash = !options.using_hash() || options.hash_function_name() == "Raw";

   if(!options.using_padding() || options.padding() == "Raw") {
      // Only valid possibility for empty padding is no hash / "Raw" hash

#if defined(BOTAN_HAS_EMSA_RAW)
      if(is_raw_hash) {
         if(options.using_prehash()) {
            if(auto hash = HashFunction::create(options.prehash_fn().value())) {
               return std::make_unique<EMSA_Raw>(hash->output_length());
            }
         } else {
            return std::make_unique<EMSA_Raw>();
         }
      }
#endif
   } else {
      const std::string padding = options.padding().value();

      // null if raw_hash
      auto hash = [&]() -> std::unique_ptr<HashFunction> {
         if(is_raw_hash) {
            return nullptr;
         } else {
            return HashFunction::create(options.hash_function_name());
         }
      }();

#if defined(BOTAN_HAS_EMSA_PKCS1)
      if(padding == "PKCS1v15") {
         if(is_raw_hash) {
            return std::make_unique<EMSA_PKCS1v15_Raw>(options.prehash_fn());
         } else if(hash) {
            return std::make_unique<EMSA_PKCS1v15>(std::move(hash));
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
      if(padding == "PSS_Raw" && hash) {
         return std::make_unique<PSSR_Raw>(std::move(hash), options.salt_size());
      }

      if(padding == "PSS" && hash) {
         return std::make_unique<PSSR>(std::move(hash), options.salt_size());
      }
#endif

#if defined(BOTAN_HAS_ISO_9796)
      if(padding == "ISO_9796_DS2" && hash) {
         //const bool implicit = req.arg(1, "exp") == "imp";
         const bool implicit = false;  // fixme
         return std::make_unique<ISO_9796_DS2>(std::move(hash), implicit, options.salt_size());
      }

      //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
      if(padding == "ISO_9796_DS3" && hash) {
         //const bool implicit = req.arg(1, "exp") == "imp";
         const bool implicit = false;  // fixme
         return std::make_unique<ISO_9796_DS3>(std::move(hash), implicit);
      }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
      if(padding == "X9.31" && hash) {
         return std::make_unique<EMSA_X931>(std::move(hash));
      }
#endif
   }

   throw Lookup_Error("Invalid or unavailable signature padding scheme " + options.to_string());
}

}  // namespace Botan
