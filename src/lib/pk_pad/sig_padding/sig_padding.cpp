/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sig_padding.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/internal/pk_options.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_X931_SIGNATURE_PADDING)
   #include <botan/internal/x931_sig_padding.h>
#endif

#if defined(BOTAN_HAS_PKCSV15_SIGNATURE_PADDING)
   #include <botan/internal/pkcs1_sig_padding.h>
#endif

#if defined(BOTAN_HAS_PSS)
   #include <botan/internal/pssr.h>
#endif

#if defined(BOTAN_HAS_RAW_SIGNATURE_PADDING)
   #include <botan/internal/raw_sig_padding.h>
#endif

#if defined(BOTAN_HAS_ISO_9796)
   #include <botan/internal/iso9796.h>
#endif

namespace Botan {

std::unique_ptr<SignaturePaddingScheme> SignaturePaddingScheme::create_or_throw(const PK_Signature_Options& options) {
   const bool is_raw_hash = !options.using_hash() || options.hash_function_name() == "Raw";

   if(!options.using_padding() || options.padding() == "Raw") {
      // Only valid possibility for empty padding is no hash / "Raw" hash

#if defined(BOTAN_HAS_EMSA_RAW)
      if(is_raw_hash) {
         if(options.using_prehash()) {
            if(auto hash = HashFunction::create(options.prehash_fn().value())) {
               return std::make_unique<SignRawBytes>(hash->output_length());
            }
         } else {
            return std::make_unique<SignRawBytes>();
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
            return std::make_unique<PKCS1v15_Raw_SignaturePaddingScheme>(options.prehash_fn());
         } else if(hash) {
            return std::make_unique<PKCS1v15_SignaturePaddingScheme>(std::move(hash));
         }
      }
#endif

#if defined(BOTAN_HAS_PSS)
      if(padding == "PSS_Raw" && hash) {
         return std::make_unique<PSS_Raw>(std::move(hash), options.salt_size());
      }

      if(padding == "PSS" && hash) {
         return std::make_unique<PSSR>(std::move(hash), options.salt_size());
      }
#endif

#if defined(BOTAN_HAS_ISO_9796)
      if(padding == "ISO_9796_DS2" && hash) {
         return std::make_unique<ISO_9796_DS2>(
            std::move(hash), !options.using_explicit_trailer_field(), options.salt_size());
      }

      //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
      if(padding == "ISO_9796_DS3" && hash) {
         return std::make_unique<ISO_9796_DS3>(std::move(hash), !options.using_explicit_trailer_field());
      }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
      if(padding == "X9.31" && hash) {
         return std::make_unique<X931_SignaturePadding>(std::move(hash));
      }
#endif
   }

   throw Lookup_Error("Invalid or unavailable signature padding scheme " + options.to_string());
}

}  // namespace Botan
