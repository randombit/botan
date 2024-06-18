/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

#if defined(BOTAN_HAS_HKDF)
   #include <botan/internal/hkdf.h>
#endif

#if defined(BOTAN_HAS_KDF1)
   #include <botan/internal/kdf1.h>
#endif

#if defined(BOTAN_HAS_KDF2)
   #include <botan/internal/kdf2.h>
#endif

#if defined(BOTAN_HAS_KDF1_18033)
   #include <botan/internal/kdf1_iso18033.h>
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
   #include <botan/internal/prf_tls.h>
#endif

#if defined(BOTAN_HAS_X942_PRF)
   #include <botan/internal/prf_x942.h>
#endif

#if defined(BOTAN_HAS_SP800_108)
   #include <botan/internal/sp800_108.h>
#endif

#if defined(BOTAN_HAS_SP800_56A)
   #include <botan/internal/sp800_56c_one_step.h>
#endif

#if defined(BOTAN_HAS_SP800_56C)
   #include <botan/internal/sp800_56c_two_step.h>
#endif

namespace Botan {

namespace {

template <typename KDF_Type>
std::unique_ptr<KDF> kdf_create_mac_or_hash(std::string_view nm) {
   if(auto mac = MessageAuthenticationCode::create(fmt("HMAC({})", nm))) {
      return std::make_unique<KDF_Type>(std::move(mac));
   }

   if(auto mac = MessageAuthenticationCode::create(nm)) {
      return std::make_unique<KDF_Type>(std::move(mac));
   }

   return nullptr;
}

}  // namespace

std::unique_ptr<KDF> KDF::create(std::string_view algo_spec, std::string_view provider) {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_HKDF)
   if(req.algo_name() == "HKDF" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<HKDF>(req.arg(0));
      }
   }

   if(req.algo_name() == "HKDF-Extract" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<HKDF_Extract>(req.arg(0));
      }
   }

   if(req.algo_name() == "HKDF-Expand" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<HKDF_Expand>(req.arg(0));
      }
   }
#endif

#if defined(BOTAN_HAS_KDF2)
   if(req.algo_name() == "KDF2" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<KDF2>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_KDF1_18033)
   if(req.algo_name() == "KDF1-18033" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<KDF1_18033>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_KDF1)
   if(req.algo_name() == "KDF1" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(req.arg(0))) {
            return std::make_unique<KDF1>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
   if(req.algo_name() == "TLS-12-PRF" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<TLS_12_PRF>(req.arg(0));
      }
   }
#endif

#if defined(BOTAN_HAS_X942_PRF)
   if(req.algo_name() == "X9.42-PRF" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<X942_PRF>(req.arg(0));
      }
   }
#endif

#if defined(BOTAN_HAS_SP800_108)
   if(req.algo_name() == "SP800-108-Counter" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<SP800_108_Counter>(req.arg(0));
      }
   }

   if(req.algo_name() == "SP800-108-Feedback" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0));
      }
   }

   if(req.algo_name() == "SP800-108-Pipeline" && req.arg_count() == 1) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<SP800_108_Pipeline>(req.arg(0));
      }
   }
#endif

#if defined(BOTAN_HAS_SP800_56A)
   if(req.algo_name() == "SP800-56A" && req.arg_count() == 1) {
      if(auto hash = HashFunction::create(req.arg(0))) {
         return std::make_unique<SP800_56C_One_Step_Hash>(std::move(hash));
      }
      if(req.arg(0) == "KMAC-128") {
         return std::make_unique<SP800_56C_One_Step_KMAC128>();
      }
      if(req.arg(0) == "KMAC-256") {
         return std::make_unique<SP800_56C_One_Step_KMAC256>();
      }
      if(auto mac = MessageAuthenticationCode::create(req.arg(0))) {
         return std::make_unique<SP800_56C_One_Step_HMAC>(std::move(mac));
      }
   }
#endif

#if defined(BOTAN_HAS_SP800_56C)
   if(req.algo_name() == "SP800-56C" && req.arg_count() == 1) {
      std::unique_ptr<KDF> exp(kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0)));
      if(exp) {
         if(auto mac = MessageAuthenticationCode::create(req.arg(0))) {
            return std::make_unique<SP800_56C_Two_Step>(std::move(mac), std::move(exp));
         }

         if(auto mac = MessageAuthenticationCode::create(fmt("HMAC({})", req.arg(0)))) {
            return std::make_unique<SP800_56C_Two_Step>(std::move(mac), std::move(exp));
         }
      }
   }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
}

//static
std::unique_ptr<KDF> KDF::create_or_throw(std::string_view algo, std::string_view provider) {
   if(auto kdf = KDF::create(algo, provider)) {
      return kdf;
   }
   throw Lookup_Error("KDF", algo, provider);
}

std::vector<std::string> KDF::providers(std::string_view algo_spec) {
   return probe_providers_of<KDF>(algo_spec);
}

}  // namespace Botan
