/*************************************************
* EMSA/EME/KDF/MGF Retrieval Source File         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/lookup.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <botan/eme.h>
#include <botan/kdf.h>
#include <botan/mgf1.h>
#include <botan/util.h>

#ifdef BOTAN_HAS_EMSA1
   #include <botan/emsa1.h>
#endif

#ifdef BOTAN_HAS_EMSA2
   #include <botan/emsa2.h>
#endif

#ifdef BOTAN_HAS_EMSA3
   #include <botan/emsa3.h>
#endif

#ifdef BOTAN_HAS_EMSA4
   #include <botan/emsa4.h>
#endif

#ifdef BOTAN_HAS_EMSA_RAW
   #include <botan/emsa_raw.h>
#endif

namespace Botan {

/*************************************************
* Get an EMSA by name                            *
*************************************************/
EMSA* get_emsa(const std::string& algo_spec)
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   const std::string emsa_name = global_state().deref_alias(name[0]);

#ifdef BOTAN_HAS_EMSA_RAW
   if(emsa_name == "Raw")
      {
      if(name.size() == 1)
         return new EMSA_Raw;
      }
#endif

#ifdef BOTAN_HAS_EMSA1
   if(emsa_name == "EMSA1")
      {
      if(name.size() == 2)
         return new EMSA1(name[1]);
      }
#endif

#ifdef BOTAN_HAS_EMSA2
   if(emsa_name == "EMSA2")
      {
      if(name.size() == 2)
         return new EMSA2(name[1]);
      }
#endif

#ifdef BOTAN_HAS_EMSA3
   if(emsa_name == "EMSA3")
      {
      if(name.size() == 2)
         return new EMSA3(name[1]);
      }
#endif

#ifdef BOTAN_HAS_EMSA4
   if(emsa_name == "EMSA4")
      {
      if(name.size() == 2)
         return new EMSA4(name[1], "MGF1");
      if(name.size() == 3)
         return new EMSA4(name[1], name[2]);
      if(name.size() == 4)
         return new EMSA4(name[1], name[2], to_u32bit(name[3]));
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

   if(eme_name == "PKCS1v15")
      {
      if(name.size() == 1)
         return new EME_PKCS1v15;
      }

   if(eme_name == "EME1")
      {
      if(name.size() == 2)
         return new EME1(name[1], "MGF1");
      if(name.size() == 3)
         return new EME1(name[1], name[2]);
      }

   throw Algorithm_Not_Found(algo_spec);
   }

/*************************************************
* Get an KDF by name                             *
*************************************************/
KDF* get_kdf(const std::string& algo_spec)
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   const std::string kdf_name = global_state().deref_alias(name[0]);

   if(kdf_name == "KDF1")
      {
      if(name.size() == 2)
         return new KDF1(name[1]);
      }

   if(kdf_name == "KDF2")
      {
      if(name.size() == 2)
         return new KDF2(name[1]);
      }

   if(kdf_name == "X9.42-PRF")
      {
      if(name.size() == 2)
         return new X942_PRF(name[1]);
      }

   if(kdf_name == "TLS-PRF")
      {
      if(name.size() == 1)
         return new TLS_PRF;
      }

   if(kdf_name == "SSL3-PRF")
      {
      if(name.size() == 1)
         return new SSL3_PRF;
      }

   throw Algorithm_Not_Found(algo_spec);
   }

/*************************************************
* Get a MGF by name                              *
*************************************************/
MGF* get_mgf(const std::string& algo_spec)
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   const std::string mgf_name = global_state().deref_alias(name[0]);

   if(mgf_name == "MGF1")
      {
      if(name.size() == 2)
         return new MGF1(get_hash(name[1]));
      }

   throw Algorithm_Not_Found(algo_spec);
   }

}
