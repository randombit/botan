/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/hash.h>
#include <botan/scan_name.h>
#include <botan/exceptn.h>

#if defined(BOTAN_HAS_HKDF)
#include <botan/hkdf.h>
#endif

#if defined(BOTAN_HAS_KDF1)
#include <botan/kdf1.h>
#endif

#if defined(BOTAN_HAS_KDF2)
#include <botan/kdf2.h>
#endif

#if defined(BOTAN_HAS_KDF1_18033)
#include <botan/kdf1_iso18033.h>
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF) || defined(BOTAN_HAS_TLS_V12_PRF)
#include <botan/prf_tls.h>
#endif

#if defined(BOTAN_HAS_X942_PRF)
#include <botan/prf_x942.h>
#endif

#if defined(BOTAN_HAS_SP800_108)
#include <botan/sp800_108.h>
#endif

#if defined(BOTAN_HAS_SP800_56A)
#include <botan/sp800_56a.h>
#endif

#if defined(BOTAN_HAS_SP800_56C)
#include <botan/sp800_56c.h>
#endif

namespace Botan {

namespace {

template<typename KDF_Type>
std::unique_ptr<KDF>
kdf_create_mac_or_hash(const std::string& nm)
   {
   if(auto mac = MessageAuthenticationCode::create(nm))
      return std::unique_ptr<KDF>(new KDF_Type(mac.release()));

   if(auto mac = MessageAuthenticationCode::create("HMAC(" + nm + ")"))
      return std::unique_ptr<KDF>(new KDF_Type(mac.release()));

   return nullptr;
   }

}

std::unique_ptr<KDF> KDF::create(const std::string& algo_spec,
                                 const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_HKDF)
   if(req.algo_name() == "HKDF" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<HKDF>(req.arg(0));
         }
      }

   if(req.algo_name() == "HKDF-Extract" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<HKDF_Extract>(req.arg(0));
         }
      }

   if(req.algo_name() == "HKDF-Expand" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<HKDF_Expand>(req.arg(0));
         }
      }
#endif

#if defined(BOTAN_HAS_KDF2)
   if(req.algo_name() == "KDF2" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::unique_ptr<KDF>(new KDF2(hash.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_KDF1_18033)
   if(req.algo_name() == "KDF1-18033" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::unique_ptr<KDF>(new KDF1_18033(hash.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_KDF1)
   if(req.algo_name() == "KDF1" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            return std::unique_ptr<KDF>(new KDF1(hash.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
   if(req.algo_name() == "TLS-PRF" && req.arg_count() == 0)
      {
      if(provider.empty() || provider == "base")
         {
         auto hmac_md5 = MessageAuthenticationCode::create("HMAC(MD5)");
         auto hmac_sha1 = MessageAuthenticationCode::create("HMAC(SHA-1)");

         if(hmac_md5 && hmac_sha1)
            return std::unique_ptr<KDF>(new TLS_PRF(std::move(hmac_md5), std::move(hmac_sha1)));
         }
      }
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
   if(req.algo_name() == "TLS-12-PRF" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<TLS_12_PRF>(req.arg(0));
         }
      }
#endif

#if defined(BOTAN_HAS_X942_PRF)
   if(req.algo_name() == "X9.42-PRF" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<KDF>(new X942_PRF(req.arg(0)));
         }
      }
#endif

#if defined(BOTAN_HAS_SP800_108)
   if(req.algo_name() == "SP800-108-Counter" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<SP800_108_Counter>(req.arg(0));
         }
      }

   if(req.algo_name() == "SP800-108-Feedback" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0));
         }
      }

   if(req.algo_name() == "SP800-108-Pipeline" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         return kdf_create_mac_or_hash<SP800_108_Pipeline>(req.arg(0));
         }
      }
#endif

#if defined(BOTAN_HAS_SP800_56A)
   if(req.algo_name() == "SP800-56A" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return std::unique_ptr<KDF>(new SP800_56A_Hash(hash.release()));
      if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
         return std::unique_ptr<KDF>(new SP800_56A_HMAC(mac.release()));
      }
#endif

#if defined(BOTAN_HAS_SP800_56C)
   if(req.algo_name() == "SP800-56C" && req.arg_count() == 1)
      {
      std::unique_ptr<KDF> exp(kdf_create_mac_or_hash<SP800_108_Feedback>(req.arg(0)));
      if(exp)
         {
         if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
            return std::unique_ptr<KDF>(new SP800_56C(mac.release(), exp.release()));

         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")"))
            return std::unique_ptr<KDF>(new SP800_56C(mac.release(), exp.release()));
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<KDF>
KDF::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto kdf = KDF::create(algo, provider))
      {
      return kdf;
      }
   throw Lookup_Error("KDF", algo, provider);
   }

std::vector<std::string> KDF::providers(const std::string& algo_spec)
   {
   return probe_providers_of<KDF>(algo_spec, { "base" });
   }

KDF* get_kdf(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(request.algo_name() == "Raw")
      return nullptr; // No KDF

   //return KDF::create_or_throw(algo_spec).release();
   auto kdf = KDF::create(algo_spec);
   if(!kdf)
      throw Algorithm_Not_Found(algo_spec);
   return kdf.release();
   }

}
