/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sig_padding.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/pk_options.h>

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
#if defined(BOTAN_HAS_EMSA_RAW)
      if(is_raw_hash) {
         return std::make_unique<SignRawBytes>(options);
      }
#endif
   } else {
      const std::string padding = options.padding().value();
      const bool hash_available = !is_raw_hash && HashFunction::create(options.hash_function_name()) != nullptr;

#if defined(BOTAN_HAS_EMSA_PKCS1)
      if(padding == "PKCS1v15") {
         if(is_raw_hash) {
            return std::make_unique<PKCS1v15_Raw_SignaturePaddingScheme>(options);
         } else if(hash_available) {
            return std::make_unique<PKCS1v15_SignaturePaddingScheme>(options);
         }
      }
#endif

#if defined(BOTAN_HAS_PSS)
      if(padding == "PSS_Raw" && hash_available) {
         return std::make_unique<PSS_Raw>(options);
      }

      if(padding == "PSS" && hash_available) {
         return std::make_unique<PSSR>(options);
      }
#endif

#if defined(BOTAN_HAS_ISO_9796)
      if(padding == "ISO_9796_DS2" && hash_available) {
         return std::make_unique<ISO_9796_DS2>(options);
      }

      if(padding == "ISO_9796_DS3" && hash_available) {
         return std::make_unique<ISO_9796_DS3>(options);
      }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
      if(padding == "X9.31" && hash_available) {
         return std::make_unique<X931_SignaturePadding>(options);
      }
#endif
   }

   throw Lookup_Error("Invalid or unavailable signature padding scheme " + options.to_string());
}

}  // namespace Botan
