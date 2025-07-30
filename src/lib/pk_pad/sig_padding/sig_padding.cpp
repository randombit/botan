/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sig_padding.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
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

std::unique_ptr<SignaturePaddingScheme> SignaturePaddingScheme::create(std::string_view algo_spec) {
   SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_EMSA_PKCS1)
   // TODO(Botan4) Remove all but "PKCS1v15"
   if(req.algo_name() == "EMSA_PKCS1" || req.algo_name() == "PKCS1v15" || req.algo_name() == "EMSA-PKCS1-v1_5" ||
      req.algo_name() == "EMSA3") {
      if(req.arg_count() == 2 && req.arg(0) == "Raw") {
         return std::make_unique<PKCS1v15_Raw_SignaturePaddingScheme>(req.arg(1));
      } else if(req.arg_count() == 1) {
         if(req.arg(0) == "Raw") {
            return std::make_unique<PKCS1v15_Raw_SignaturePaddingScheme>();
         } else {
            if(auto hash = HashFunction::create(req.arg(0))) {
               return std::make_unique<PKCS1v15_SignaturePaddingScheme>(std::move(hash));
            }
         }
      }
   }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   // TODO(Botan4) Remove all but "PSS_Raw"
   if(req.algo_name() == "PSS_Raw" || req.algo_name() == "PSSR_Raw") {
      if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            if(req.arg_count() == 3) {
               const size_t salt_size = req.arg_as_integer(2, 0);
               return std::make_unique<PSS_Raw>(std::move(hash), salt_size);
            } else {
               return std::make_unique<PSS_Raw>(std::move(hash));
            }
         }
      }
   }

   // TODO(Botan4) Remove all but "PSS"
   if(req.algo_name() == "PSS" || req.algo_name() == "PSSR" || req.algo_name() == "EMSA-PSS" ||
      req.algo_name() == "PSS-MGF1" || req.algo_name() == "EMSA4") {
      if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            if(req.arg_count() == 3) {
               const size_t salt_size = req.arg_as_integer(2, 0);
               return std::make_unique<PSSR>(std::move(hash), salt_size);
            } else {
               return std::make_unique<PSSR>(std::move(hash));
            }
         }
      }
   }
#endif

#if defined(BOTAN_HAS_ISO_9796)
   if(req.algo_name() == "ISO_9796_DS2") {
      if(req.arg_count_between(1, 3)) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            const size_t salt_size = req.arg_as_integer(2, hash->output_length());
            const bool implicit = req.arg(1, "exp") == "imp";
            return std::make_unique<ISO_9796_DS2>(std::move(hash), implicit, salt_size);
         }
      }
   }
   //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
   if(req.algo_name() == "ISO_9796_DS3") {
      if(req.arg_count_between(1, 2)) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            const bool implicit = req.arg(1, "exp") == "imp";
            return std::make_unique<ISO_9796_DS3>(std::move(hash), implicit);
         }
      }
   }
#endif

#if defined(BOTAN_HAS_X931_SIGNATURE_PADDING)
   // TODO(Botan4) Remove all but "X9.31"
   if(req.algo_name() == "EMSA_X931" || req.algo_name() == "EMSA2" || req.algo_name() == "X9.31") {
      if(req.arg_count() == 1) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<X931_SignaturePadding>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_RAW_SIGNATURE_PADDING)
   if(req.algo_name() == "Raw") {
      if(req.arg_count() == 0) {
         return std::make_unique<SignRawBytes>();
      } else {
         auto hash = HashFunction::create(req.arg(0));
         if(hash) {
            return std::make_unique<SignRawBytes>(hash->output_length());
         }
      }
   }
#endif

   return nullptr;
}

std::unique_ptr<SignaturePaddingScheme> SignaturePaddingScheme::create_or_throw(std::string_view algo_spec) {
   if(auto padding = SignaturePaddingScheme::create(algo_spec)) {
      return padding;
   } else {
      throw Algorithm_Not_Found(algo_spec);
   }
}

}  // namespace Botan
