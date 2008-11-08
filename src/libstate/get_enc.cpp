/*************************************************
* EMSA/EME/KDF/MGF Retrieval Source File         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <botan/util.h>

#if defined(BOTAN_HAS_MGF1)
  #include <botan/mgf1.h>
#endif

#if defined(BOTAN_HAS_EMSA1)
  #include <botan/emsa1.h>
#endif

#if defined(BOTAN_HAS_EMSA1_BSI)
  #include <botan/emsa1_bsi.h>
#endif

#if defined(BOTAN_HAS_EMSA2)
  #include <botan/emsa2.h>
#endif

#if defined(BOTAN_HAS_EMSA3)
  #include <botan/emsa3.h>
#endif

#if defined(BOTAN_HAS_EMSA4)
  #include <botan/emsa4.h>
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
  #include <botan/emsa_raw.h>
#endif

#if defined(BOTAN_HAS_EME1)
  #include <botan/eme1.h>
#endif

#if defined(BOTAN_HAS_EME_PKCS1v15)
  #include <botan/eme_pkcs.h>
#endif

#if defined(BOTAN_HAS_KDF1)
  #include <botan/kdf1.h>
#endif

#if defined(BOTAN_HAS_KDF2)
  #include <botan/kdf2.h>
#endif

#if defined(BOTAN_HAS_X942_PRF)
  #include <botan/prf_x942.h>
#endif

#if defined(BOTAN_HAS_SSL_V3_PRF)
  #include <botan/prf_ssl3.h>
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
  #include <botan/prf_tls.h>
#endif

namespace Botan {

/*************************************************
* Get an EMSA by name                            *
*************************************************/
EMSA* get_emsa(const std::string& algo_spec)
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   const std::string emsa_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_EMSA_RAW)
   if(emsa_name == "Raw")
      {
      if(name.size() == 1)
         return new EMSA_Raw;
      }
#endif

#if defined(BOTAN_HAS_EMSA1)
   if(emsa_name == "EMSA1")
      {
      if(name.size() == 2)
         return new EMSA1(get_hash(name[1]));
      }
#endif

#if defined(BOTAN_HAS_EMSA1_BSI)
   if(emsa_name == "EMSA1_BSI")
      {
      if(name.size() == 2)
         return new EMSA1_BSI(get_hash(name[1]));
      }
#endif

#if defined(BOTAN_HAS_EMSA2)
   if(emsa_name == "EMSA2")
      {
      if(name.size() == 2)
         return new EMSA2(get_hash(name[1]));
      }
#endif

#if defined(BOTAN_HAS_EMSA3)
   if(emsa_name == "EMSA3")
      {
      if(name.size() == 2)
         return new EMSA3(get_hash(name[1]));
      }
#endif

#if defined(BOTAN_HAS_EMSA4)
   if(emsa_name == "EMSA4")
      {
      // EMSA4 is hardcoded to use MGF1
      if(name.size() >= 3 && name[2] != "MGF1")
         throw Algorithm_Not_Found(algo_spec);

      if(name.size() == 2 || name.size() == 3)
         return new EMSA4(get_hash(name[1]));
      else if(name.size() == 4)
         return new EMSA4(get_hash(name[1]), to_u32bit(name[3]));
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

/*************************************************
* Get an EME by name                             *
*************************************************/
EME* get_eme(const std::string& algo_spec)
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   const std::string eme_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_EME_PKCS1v15)
   if(eme_name == "PKCS1v15")
      {
      if(name.size() == 1)
         return new EME_PKCS1v15;
      }
#endif

#if defined(BOTAN_HAS_EME1)
   if(eme_name == "EME1")
      {
      if(name.size() >= 2)
         {
         if(name.size() >= 3)
            {
            // EME1 is hardcoded for MGF1
            if(name[2] != "MGF1")
               throw Algorithm_Not_Found(algo_spec);
            }

         return new EME1(get_hash(name[1]));
         }
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

/*************************************************
* Get an KDF by name                             *
*************************************************/
KDF* get_kdf(const std::string& algo_spec)
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   const std::string kdf_name = global_state().deref_alias(name[0]);

#if defined(BOTAN_HAS_KDF1)
   if(kdf_name == "KDF1")
      {
      if(name.size() == 2)
         return new KDF1(get_hash(name[1]));
      }
#endif

#if defined(BOTAN_HAS_KDF2)
   if(kdf_name == "KDF2")
      {
      if(name.size() == 2)
         return new KDF2(get_hash(name[1]));
      }
#endif

#if defined(BOTAN_HAS_X942_PRF)
   if(kdf_name == "X9.42-PRF")
      {
      if(name.size() == 2)
         return new X942_PRF(name[1]);
      }
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
   if(kdf_name == "TLS-PRF")
      {
      if(name.size() == 1)
         return new TLS_PRF;
      }
#endif

#if defined(BOTAN_HAS_SSL_V3_PRF)
   if(kdf_name == "SSL3-PRF")
      {
      if(name.size() == 1)
         return new SSL3_PRF;
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

}
