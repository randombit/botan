/*************************************************
* PBE Retrieval Source File                      *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/get_pbe.h>
#include <botan/oids.h>
#include <botan/scan_name.h>
#include <botan/parsing.h>
#include <botan/libstate.h>

#if defined(BOTAN_HAS_PBE_PKCS_V15)
  #include <botan/pbes1.h>
#endif

#if defined(BOTAN_HAS_PBE_PKCS_V20)
  #include <botan/pbes2.h>
#endif

namespace Botan {

namespace {

PBE* make_pbe_pkcs15(const std::string& cipher,
                     const std::string& digest,
                     Cipher_Dir direction)
   {
   std::vector<std::string> cipher_spec = split_on(cipher, '/');
   if(cipher_spec.size() != 2)
      throw Invalid_Argument("PBE-PKCS5 v1.5: Invalid cipher spec " + cipher);

   const std::string cipher_algo = global_state().deref_alias(cipher_spec[0]);
   const std::string cipher_mode = cipher_spec[1];

   if(cipher_mode != "CBC")
      throw Invalid_Argument("PBE-PKCS5 v1.5: Invalid cipher " + cipher);

   Algorithm_Factory& af = global_state().algorithm_factory();

   const BlockCipher* block_cipher = af.make_block_cipher(cipher_algo);
   if(!block_cipher)
      throw Algorithm_Not_Found(cipher_algo);

   const HashFunction* hash_function = af.make_hash_function(digest);
   if(!hash_function)
      throw Algorithm_Not_Found(digest);

   return new PBE_PKCS5v15(block_cipher->clone(),
                           hash_function->clone(),
                           direction);

   }

}

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
      return make_pbe_pkcs15(cipher, digest, ENCRYPTION);
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

      PBE* pbe = make_pbe_pkcs15(cipher, digest, DECRYPTION);
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
