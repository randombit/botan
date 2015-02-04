/*
* EMSA/EME Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa.h>
#include <botan/eme.h>
#include <botan/scan_name.h>
#include <botan/internal/algo_registry.h>

namespace Botan {

EMSA* get_emsa(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(EMSA* emsa = make_a<EMSA>(algo_spec))
      return emsa;

   throw Algorithm_Not_Found(algo_spec);
   }

EME* get_eme(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(EME* eme = make_a<EME>(algo_spec))
      return eme;

   if(request.algo_name() == "Raw")
      return nullptr; // No padding

   throw Algorithm_Not_Found(algo_spec);
   }

}
