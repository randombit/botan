/*************************************************
* PBE Retrieval Source File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/get_pbe.h>
#include <botan/oids.h>
#include <botan/parsing.h>

#if defined(BOTAN_HAS_PBE_PKCS_V15)
  #include <botan/pbes1.h>
#endif

#if defined(BOTAN_HAS_PBE_PKCS_V20)
  #include <botan/pbes2.h>
#endif

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

#if defined(BOTAN_HAS_PBE_PKCS_V15)
   if(pbe == "PBE-PKCS5v15")
      return new PBE_PKCS5v15(digest, cipher, ENCRYPTION);
#endif

#if defined(BOTAN_HAS_PBE_PKCS_V20)
   if(pbe == "PBE-PKCS5v20")
      return new PBE_PKCS5v20(digest, cipher);
#endif

   throw Algorithm_Not_Found(pbe_name);
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

#if defined(BOTAN_HAS_PBE_PKCS_V15)
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
#endif

#if defined(BOTAN_HAS_PBE_PKCS_V20)
   if(pbe_algo == "PBE-PKCS5v20")
      return new PBE_PKCS5v20(params);
#endif

   throw Algorithm_Not_Found(pbe_oid.as_string());
   }

}
