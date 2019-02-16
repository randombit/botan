/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa.h>
#include <botan/hash.h>
#include <botan/scan_name.h>
#include <botan/exceptn.h>

#if defined(BOTAN_HAS_EMSA1)
   #include <botan/emsa1.h>
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

#if defined(BOTAN_HAS_ISO_9796)
   #include <botan/iso9796.h>
#endif

namespace Botan {

AlgorithmIdentifier EMSA::config_for_x509(const Private_Key&,
                                          const std::string&) const
   {
   throw Not_Implemented("Encoding " + name() + " not supported for signing X509 objects");
   }

EMSA* get_emsa(const std::string& algo_spec)
   {
   SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_EMSA1)
   if(req.algo_name() == "EMSA1" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         return new EMSA1(hash.release());
      }
#endif

#if defined(BOTAN_HAS_EMSA_PKCS1)
   if(req.algo_name() == "EMSA_PKCS1" ||
      req.algo_name() == "PKCS1v15" ||
      req.algo_name() == "EMSA-PKCS1-v1_5" ||
      req.algo_name() == "EMSA3")
      {
      if(req.arg_count() == 2 && req.arg(0) == "Raw")
         {
         return new EMSA_PKCS1v15_Raw(req.arg(1));
         }
      else if(req.arg_count() == 1)
         {
         if(req.arg(0) == "Raw")
            {
            return new EMSA_PKCS1v15_Raw;
            }
         else
            {
            if(auto hash = HashFunction::create(req.arg(0)))
               {
               return new EMSA_PKCS1v15(hash.release());
               }
            }
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_PSSR)
   if(req.algo_name() == "PSS_Raw" ||
      req.algo_name() == "PSSR_Raw")
      {
      if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1")
         {
         if(auto h = HashFunction::create(req.arg(0)))
            {
            if(req.arg_count() == 3)
               {
               const size_t salt_size = req.arg_as_integer(2, 0);
               return new PSSR_Raw(h.release(), salt_size);
               }
            else
               {
               return new PSSR_Raw(h.release());
               }
            }
         }
      }

   if(req.algo_name() == "PSS" ||
      req.algo_name() == "PSSR" ||
      req.algo_name() == "EMSA-PSS" ||
      req.algo_name() == "PSS-MGF1" ||
      req.algo_name() == "EMSA4")
      {
      if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1")
         {
         if(auto h = HashFunction::create(req.arg(0)))
            {
            if(req.arg_count() == 3)
               {
               const size_t salt_size = req.arg_as_integer(2, 0);
               return new PSSR(h.release(), salt_size);
               }
            else
               {
               return new PSSR(h.release());
               }
            }
         }
      }
#endif

#if defined(BOTAN_HAS_ISO_9796)
   if(req.algo_name() == "ISO_9796_DS2")
      {
      if(req.arg_count_between(1, 3))
         {
         if(auto h = HashFunction::create(req.arg(0)))
            {
            const size_t salt_size = req.arg_as_integer(2, h->output_length());
            const bool implicit = req.arg(1, "exp") == "imp";
            return new ISO_9796_DS2(h.release(), implicit, salt_size);
            }
         }
      }
   //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
   if(req.algo_name() == "ISO_9796_DS3")
      {
      if(req.arg_count_between(1, 2))
         {
         if(auto h = HashFunction::create(req.arg(0)))
            {
            const bool implicit = req.arg(1, "exp") == "imp";
            return new ISO_9796_DS3(h.release(), implicit);
            }
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_X931)
   if(req.algo_name() == "EMSA_X931" ||
         req.algo_name() == "EMSA2" ||
         req.algo_name() == "X9.31")
      {
      if(req.arg_count() == 1)
         {
         if(auto hash = HashFunction::create(req.arg(0)))
            {
            return new EMSA_X931(hash.release());
            }
         }
      }
#endif

#if defined(BOTAN_HAS_EMSA_RAW)
   if(req.algo_name() == "Raw")
      {
      if(req.arg_count() == 0)
         {
         return new EMSA_Raw;
         }
      else
         {
         auto hash = HashFunction::create(req.arg(0));
         if(hash)
            return new EMSA_Raw(hash->output_length());
         }
      }
#endif

   throw Algorithm_Not_Found(algo_spec);
   }

std::string hash_for_emsa(const std::string& algo_spec)
   {
   SCAN_Name emsa_name(algo_spec);

   if(emsa_name.arg_count() > 0)
      {
      const std::string pos_hash = emsa_name.arg(0);
      return pos_hash;
      }

   // If we don't understand what this is return a safe default
#if defined(BOTAN_HAS_SHA2_64)
   return "SHA-512";
#else
   return "SHA-256";
#endif
   }

}
