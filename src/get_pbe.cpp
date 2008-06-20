/*************************************************
* PBE Retrieval Source File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/oids.h>
#include <botan/lookup.h>
#include <botan/pbe_pkcs.h>
#include <botan/parsing.h>

namespace Botan {

/*************************************************
* Get an encryption PBE, set new parameters      *
*************************************************/
PBE* get_pbe(const std::string& pbe_name)
   {
   std::vector<std::string> algo_name;
   algo_name = parse_algorithm_name(pbe_name);

   if(algo_name.size() != 3)
      throw Invalid_Algorithm_Name(pbe_name);

   const std::string pbe = algo_name[0];
   const std::string digest = algo_name[1];
   const std::string cipher = algo_name[2];

   PBE* pbe_obj = 0;

   if(pbe == "PBE-PKCS5v15")
      pbe_obj = new PBE_PKCS5v15(digest, cipher, ENCRYPTION);
   else if(pbe == "PBE-PKCS5v20")
      pbe_obj = new PBE_PKCS5v20(digest, cipher);

   if(!pbe_obj)
      throw Algorithm_Not_Found(pbe_name);

   return pbe_obj;
   }

/*************************************************
* Get a decryption PBE, decode parameters        *
*************************************************/
PBE* get_pbe(const OID& pbe_oid, DataSource& params)
   {
   std::vector<std::string> algo_name;
   algo_name = parse_algorithm_name(OIDS::lookup(pbe_oid));

   if(algo_name.size() < 1)
      throw Invalid_Algorithm_Name(pbe_oid.as_string());
   const std::string pbe_algo = algo_name[0];

   if(pbe_algo == "PBE-PKCS5v15")
      {
      if(algo_name.size() != 3)
         throw Invalid_Algorithm_Name(pbe_oid.as_string());
      const std::string digest = algo_name[1];
      const std::string cipher = algo_name[2];
      PBE* pbe = new PBE_PKCS5v15(digest, cipher, DECRYPTION);
      pbe->decode_params(params);
      return pbe;
      }
   else if(pbe_algo == "PBE-PKCS5v20")
      return new PBE_PKCS5v20(params);

   throw Algorithm_Not_Found(pbe_oid.as_string());
   }

}
