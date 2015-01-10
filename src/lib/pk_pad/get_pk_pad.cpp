/*
* EMSA/EME Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa.h>
#include <botan/eme.h>
#include <botan/libstate.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_EMSA1)
  #include <botan/emsa1.h>
#endif

#if defined(BOTAN_HAS_EMSA1_BSI)
  #include <botan/emsa1_bsi.h>
#endif

#if defined(BOTAN_HAS_EMSA_X931)
  #include <botan/emsa_x931.h>
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
  #include <botan/emsa_pkcs1.h>
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
  #include <botan/pssr.h>
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
  #include <botan/emsa_raw.h>
#endif

#if defined(BOTAN_HAS_EME_OAEP)
  #include <botan/oaep.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
  #include <botan/eme_pkcs.h>
#endif

namespace Botan {

/*
* Get an EMSA by name
*/
EMSA* get_emsa(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   Algorithm_Factory& af = global_state().algorithm_factory();

#if defined(BOTAN_HAS_EMSA_RAW)
   if(request.algo_name() == "Raw" && request.arg_count() == 0)
      return new EMSA_Raw;
#endif

   if(request.algo_name() == "EMSA1" && request.arg_count() == 1)
      {
#if defined(BOTAN_HAS_EMSA_RAW)
      if(request.arg(0) == "Raw")
         return new EMSA_Raw;
#endif

#if defined(BOTAN_HAS_EMSA1)
      return new EMSA1(af.make_hash_function(request.arg(0)));
#endif
      }

#if defined(BOTAN_HAS_EMSA1_BSI)
   if(request.algo_name() == "EMSA1_BSI" && request.arg_count() == 1)
      return new EMSA1_BSI(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_EMSA_X931)
   if(request.algo_name() == "EMSA_X931" && request.arg_count() == 1)
      return new EMSA_X931(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
   if(request.algo_name() == "EMSA_PKCS1" && request.arg_count() == 1)
      {
      if(request.arg(0) == "Raw")
         return new EMSA_PKCS1v15_Raw;
      return new EMSA_PKCS1v15(af.make_hash_function(request.arg(0)));
      }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   if(request.algo_name() == "PSSR" && request.arg_count_between(1, 3))
      {
      // 3 args: Hash, MGF, salt size (MGF is hardcoded MGF1 in Botan)
      if(request.arg_count() == 1)
         return new PSSR(af.make_hash_function(request.arg(0)));

      if(request.arg_count() == 2 && request.arg(1) != "MGF1")
         return new PSSR(af.make_hash_function(request.arg(0)));

      if(request.arg_count() == 3)
         return new PSSR(af.make_hash_function(request.arg(0)),
                         request.arg_as_integer(2, 0));
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

/*
* Get an EME by name
*/
EME* get_eme(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(request.algo_name() == "Raw")
      return nullptr; // No padding

#if defined(BOTAN_HAS_EME_PKCS1v15)
   if(request.algo_name() == "PKCS1v15" && request.arg_count() == 0)
      return new EME_PKCS1v15;
#endif

#if defined(BOTAN_HAS_EME_OAEP)
   Algorithm_Factory& af = global_state().algorithm_factory();

   if(request.algo_name() == "OAEP" && request.arg_count_between(1, 2))
      {
      if(request.arg_count() == 1 ||
         (request.arg_count() == 2 && request.arg(1) == "MGF1"))
         {
         return new OAEP(af.make_hash_function(request.arg(0)));
         }
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

}
