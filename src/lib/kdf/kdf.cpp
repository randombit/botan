/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf.h>
#include <botan/internal/kdf_utils.h>

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

namespace Botan {

KDF* get_kdf(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(request.algo_name() == "Raw")
      return nullptr; // No KDF

   if(KDF* kdf = make_a<KDF>(algo_spec))
      return kdf;
   throw Algorithm_Not_Found(algo_spec);
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
