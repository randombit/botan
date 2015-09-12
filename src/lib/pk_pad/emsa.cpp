/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa.h>
#include <botan/internal/pad_utils.h>

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

namespace Botan {

EMSA::~EMSA() {}

EMSA* get_emsa(const std::string& algo_spec)
   {
   SCAN_Name request(algo_spec);

   if(EMSA* emsa = make_a<EMSA>(algo_spec))
      return emsa;

   throw Algorithm_Not_Found(algo_spec);
   }

#if defined(BOTAN_HAS_EMSA1)
BOTAN_REGISTER_EMSA_1HASH(EMSA1, "EMSA1");
#endif

#if defined(BOTAN_HAS_EMSA1_BSI)
BOTAN_REGISTER_EMSA_1HASH(EMSA1_BSI, "EMSA1_BSI");
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
BOTAN_REGISTER_NAMED_T(EMSA, "EMSA_PKCS1", EMSA_PCS1v15, EMSA_PKCS1v15::make);
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
BOTAN_REGISTER_NAMED_T(EMSA, "PSSR", PSSR, PSSR::make);
#endif

#if defined(BOTAN_HAS_EMSA_X931)
BOTAN_REGISTER_EMSA_1HASH(EMSA_X931, "EMSA_X931");
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
BOTAN_REGISTER_EMSA_NAMED_NOARGS(EMSA_Raw, "Raw");
#endif

}


