/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/probe_providers.h>

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

template <typename KDF_Type, typename... ParamTs>
std::unique_ptr<KDF> kdf_create_mac_or_hash(std::string_view nm, ParamTs&&... params) {
   if(auto mac = MessageAuthenticationCode::create(fmt("HMAC({})", nm))) {
      return std::make_unique<KDF_Type>(std::move(mac), std::forward<ParamTs>(params)...);
   }

   if(auto mac = MessageAuthenticationCode::create(nm)) {
      return std::make_unique<KDF_Type>(std::move(mac), std::forward<ParamTs>(params)...);
   }

   return nullptr;
}

}  // namespace

std::unique_ptr<KDF> KDF::create(std::string_view algo_spec, std::string_view provider) {
   const AlgorithmSpec req(algo_spec);

#if defined(BOTAN_HAS_HKDF)
   if(auto m = req.match("HKDF({prf})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<HKDF>(m->str("prf"));
      }
   }

   if(auto m = req.match("HKDF-Extract({prf})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<HKDF_Extract>(m->str("prf"));
      }
   }

   if(auto m = req.match("HKDF-Expand({prf})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<HKDF_Expand>(m->str("prf"));
      }
   }
#endif

#if defined(BOTAN_HAS_KDF2)
   if(auto m = req.match("KDF2({hash})")) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(m->str("hash"))) {
            return std::make_unique<KDF2>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_KDF1_18033)
   if(auto m = req.match("KDF1-18033({hash})")) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(m->str("hash"))) {
            return std::make_unique<KDF1_18033>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_KDF1)
   if(auto m = req.match("KDF1({hash})")) {
      if(provider.empty() || provider == "base") {
         if(auto hash = HashFunction::create(m->str("hash"))) {
            return std::make_unique<KDF1>(std::move(hash));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
   if(auto m = req.match("TLS-12-PRF({prf})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<TLS_12_PRF>(m->str("prf"));
      }
   }
#endif

#if defined(BOTAN_HAS_X942_PRF)
   if(auto m = req.match("X9.42-PRF({kek:str})")) {
      if(provider.empty() || provider == "base") {
         return std::make_unique<X942_PRF>(m->str("kek"));
      }
   }
#endif

#if defined(BOTAN_HAS_SP800_108)
   if(auto m = req.match("SP800-108-Counter({prf},{r:int=32},{L:int=32})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<SP800_108_Counter>(m->str("prf"), m->integer("r"), m->integer("L"));
      }
   }

   if(auto m = req.match("SP800-108-Feedback({prf},{r:int=32},{L:int=32})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<SP800_108_Feedback>(m->str("prf"), m->integer("r"), m->integer("L"));
      }
   }

   if(auto m = req.match("SP800-108-Pipeline({prf},{r:int=32},{L:int=32})")) {
      if(provider.empty() || provider == "base") {
         return kdf_create_mac_or_hash<SP800_108_Pipeline>(m->str("prf"), m->integer("r"), m->integer("L"));
      }
   }
#endif

#if defined(BOTAN_HAS_SP800_56A)
   if(auto m = req.match("SP800-56A({fn})")) {
      if(provider.empty() || provider == "base") {
         const auto fn = m->str("fn");
         if(auto hash = HashFunction::create(fn)) {
            return std::make_unique<SP800_56C_One_Step_Hash>(std::move(hash));
         }
         if(fn == "KMAC-128") {
            return std::make_unique<SP800_56C_One_Step_KMAC128>();
         }
         if(fn == "KMAC-256") {
            return std::make_unique<SP800_56C_One_Step_KMAC256>();
         }
         if(auto mac = MessageAuthenticationCode::create(fn)) {
            return std::make_unique<SP800_56C_One_Step_HMAC>(std::move(mac));
         }
      }
   }
#endif

#if defined(BOTAN_HAS_SP800_56C)
   if(auto m = req.match("SP800-56C({prf})")) {
      if(provider.empty() || provider == "base") {
         const auto prf = m->str("prf");
         std::unique_ptr<KDF> exp(kdf_create_mac_or_hash<SP800_108_Feedback>(prf, 32, 32));
         if(exp) {
            if(auto mac = MessageAuthenticationCode::create(fmt("HMAC({})", prf))) {
               return std::make_unique<SP800_56C_Two_Step>(std::move(mac), std::move(exp));
            }

            if(auto mac = MessageAuthenticationCode::create(prf)) {
               return std::make_unique<SP800_56C_Two_Step>(std::move(mac), std::move(exp));
            }
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

//static
std::span<const uint8_t> KDF::_as_span(std::string_view s) {
   return as_span_of_bytes(s);
}

}  // namespace Botan
