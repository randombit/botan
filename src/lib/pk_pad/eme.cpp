/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/eme.h>

#include <botan/exceptn.h>
#include <botan/internal/parsing.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_EME_OAEP)
   #include <botan/internal/oaep.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1)
   #include <botan/internal/eme_pkcs.h>
#endif

#if defined(BOTAN_HAS_EME_RAW)
   #include <botan/internal/eme_raw.h>
#endif

namespace Botan {

std::unique_ptr<EME> EME::create(std::string_view algo_spec) {
#if defined(BOTAN_HAS_EME_RAW)
   if(algo_spec == "Raw") {
      return std::make_unique<EME_Raw>();
   }
#endif

#if defined(BOTAN_HAS_EME_PKCS1)
   // TODO(Botan4) Remove all but "PKCS1v15"
   if(algo_spec == "PKCS1v15" || algo_spec == "EME-PKCS1-v1_5") {
      return std::make_unique<EME_PKCS1v15>();
   }
#endif

#if defined(BOTAN_HAS_EME_OAEP)
   SCAN_Name req(algo_spec);

   // TODO(Botan4) Remove all but "OAEP"
   if(req.algo_name() == "OAEP" || req.algo_name() == "EME-OAEP" || req.algo_name() == "EME1") {
      if(req.arg_count() == 1 || ((req.arg_count() == 2 || req.arg_count() == 3) && req.arg(1) == "MGF1")) {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<OAEP>(std::move(hash), req.arg(2, ""));
         }
      } else if(req.arg_count() == 2 || req.arg_count() == 3) {
         auto mgf_params = parse_algorithm_name(req.arg(1));

         if(mgf_params.size() == 2 && mgf_params[0] == "MGF1") {
            auto hash = HashFunction::create(req.arg(0));
            auto mgf1_hash = HashFunction::create(mgf_params[1]);

            if(hash && mgf1_hash) {
               return std::make_unique<OAEP>(std::move(hash), std::move(mgf1_hash), req.arg(2, ""));
            }
         }
      }
   }
#endif

   throw Algorithm_Not_Found(algo_spec);
}

EME::~EME() = default;

}  // namespace Botan
