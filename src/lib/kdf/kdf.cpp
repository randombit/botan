/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf.h>
#include <botan/internal/algo_registry.h>
#include <botan/exceptn.h>

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

}
