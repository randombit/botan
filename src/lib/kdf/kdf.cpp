/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf.h>
#include <botan/exceptn.h>
#include <botan/internal/algo_registry.h>

#if defined(BOTAN_HAS_HKDF)
#include <botan/hkdf.h>
#endif

#if defined(BOTAN_HAS_KDF1)
#include <botan/kdf1.h>
#endif

#if defined(BOTAN_HAS_KDF2)
#include <botan/kdf2.h>
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
#include <botan/prf_tls.h>
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
#include <botan/prf_tls.h>
#endif

#if defined(BOTAN_HAS_X942_PRF)
#include <botan/prf_x942.h>
#endif

#define BOTAN_REGISTER_KDF_NOARGS(type, name)                    \
   BOTAN_REGISTER_NAMED_T(KDF, name, type, (make_new_T<type>))
#define BOTAN_REGISTER_KDF_1HASH(type, name)                    \
   BOTAN_REGISTER_NAMED_T(KDF, name, type, (make_new_T_1X<type, HashFunction>))

#define BOTAN_REGISTER_KDF_NAMED_1STR(type, name) \
   BOTAN_REGISTER_NAMED_T(KDF, name, type, (make_new_T_1str_req<type>))

namespace Botan {

KDF::~KDF() {}

std::unique_ptr<KDF> KDF::create(const std::string& algo_spec,
                                                 const std::string& provider)
   {
   return std::unique_ptr<KDF>(make_a<KDF>(Botan::KDF::Spec(algo_spec), provider));
   }

std::vector<std::string> KDF::providers(const std::string& algo_spec)
   {
   return providers_of<KDF>(KDF::Spec(algo_spec));
   }

KDF* get_kdf(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(request.algo_name() == "Raw")
      return nullptr; // No KDF

   auto kdf = KDF::create(algo_spec);
   if(!kdf)
      throw Algorithm_Not_Found(algo_spec);
   return kdf.release();
   }

#if defined(BOTAN_HAS_HKDF)
BOTAN_REGISTER_NAMED_T(KDF, "HKDF", HKDF, HKDF::make);
#endif

#if defined(BOTAN_HAS_KDF1)
BOTAN_REGISTER_KDF_1HASH(KDF1, "KDF1");
#endif

#if defined(BOTAN_HAS_KDF2)
BOTAN_REGISTER_KDF_1HASH(KDF2, "KDF2");
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
BOTAN_REGISTER_KDF_NOARGS(TLS_PRF, "TLS-PRF");
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
BOTAN_REGISTER_NAMED_T(KDF, "TLS-12-PRF", TLS_12_PRF, TLS_12_PRF::make);
#endif

#if defined(BOTAN_HAS_X942_PRF)
BOTAN_REGISTER_KDF_NAMED_1STR(X942_PRF, "X9.42-PRF");
#endif

}
