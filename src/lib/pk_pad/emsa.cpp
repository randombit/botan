/*
* (C) 2015,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/emsa.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/pk_options.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

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
   if(options.using_hash() && options.using_padding()) {
      return EMSA::create_or_throw(fmt("{}({})", options.padding().value(), options.hash_function_name()));
   }

   if(options.using_padding()) {
      return EMSA::create_or_throw(options.padding().value());
   }

   if(options.using_hash()) {
      return EMSA::create_or_throw(options.hash_function_name());
   }

   throw Invalid_Argument("This signature scheme requires you specify a padding mode");
}

std::unique_ptr<EMSA> EMSA::create(std::string_view algo_spec) {
   SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_EMSA_PKCS1)
   if(req.algo_name() == "EMSA_PKCS1" || req.algo_name() == "PKCS1v15" || req.algo_name() == "EMSA-PKCS1-v1_5" ||
      req.algo_name() == "EMSA3") {
      if(req.arg_count() == 2 && req.arg(0) == "Raw") {
         return std::make_unique<EMSA_PKCS1v15_Raw>(req.arg(1));
      } else if(req.arg_count() == 1) {
         if(req.arg(0) == "Raw") {
            return std::make_unique<EMSA_PKCS1v15_Raw>();
         } else {
            if(auto hash = HashFunction::create(req.arg(0))) {
               return std::make_unique<EMSA_PKCS1v15>(std::move(hash));
            }
         }
      }
   }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   if(req.algo_name() == "PSS_Raw" || req.algo_name() == "PSSR_Raw") {
      if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            if(req.arg_count() == 3) {
               const size_t salt_size = req.arg_as_integer(2, 0);
               return std::make_unique<PSSR_Raw>(std::move(hash), salt_size);
            } else {
               return std::make_unique<PSSR_Raw>(std::move(hash));
            }
         }
      }
   }

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

#if defined(BOTAN_HAS_EMSA_X931)
   if(req.algo_name() == "EMSA_X931" || req.algo_name() == "EMSA2" || req.algo_name() == "X9.31") {
      if(req.arg_count() == 1) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<EMSA_X931>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
   if(req.algo_name() == "Raw") {
      if(req.arg_count() == 0) {
         return std::make_unique<EMSA_Raw>();
      } else {
         auto hash = HashFunction::create(req.arg(0));
         if(hash) {
            return std::make_unique<EMSA_Raw>(hash->output_length());
         }
      }
   }
#endif

   return nullptr;
}

std::unique_ptr<EMSA> EMSA::create_or_throw(std::string_view algo_spec) {
   auto emsa = EMSA::create(algo_spec);
   if(emsa) {
      return emsa;
   }
   throw Algorithm_Not_Found(algo_spec);
}

}  // namespace Botan
