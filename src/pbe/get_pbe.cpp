/*************************************************
* PBE Retrieval Source File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/get_pbe.h>
#include <botan/oids.h>
#include <botan/scan_name.h>

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
   SCAN_Name request(pbe_name);

   if(request.arg_count() != 2)
      throw Invalid_Algorithm_Name(pbe_name);

   const std::string pbe = request.algo_name();
   const std::string digest = request.arg(0);
   const std::string cipher = request.arg(1);

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
   SCAN_Name request(OIDS::lookup(pbe_oid));

#if defined(BOTAN_HAS_PBE_PKCS_V15)
   if(request.algo_name() == "PBE-PKCS5v15")
      {
      if(request.arg_count() != 2)
         throw Invalid_Algorithm_Name(pbe_oid.as_string());

      const std::string digest = request.arg(0);
      const std::string cipher = request.arg(1);

      PBE* pbe = new PBE_PKCS5v15(digest, cipher, DECRYPTION);
      pbe->decode_params(params);
      return pbe;
      }
#endif

#if defined(BOTAN_HAS_PBE_PKCS_V20)
   if(request.algo_name() == "PBE-PKCS5v20")
      return new PBE_PKCS5v20(params);
#endif

   throw Algorithm_Not_Found(pbe_oid.as_string());
   }

}
