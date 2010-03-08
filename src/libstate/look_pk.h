/*
* PK Algorithm Lookup
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PK_LOOKUP_H__
#define BOTAN_PK_LOOKUP_H__

#include <botan/lookup.h>
#include <botan/pubkey.h>

namespace Botan {

/**
* Public key encryptor factory method.
* @param key the key that will work inside the encryptor
* @param eme determines the algorithm and encoding
* @return the public key encryptor object
*/
inline PK_Encryptor* get_pk_encryptor(const Public_Key& key,
                                      const std::string& eme)
   {
   return new PK_Encryptor_MR_with_EME(key, eme);
   }

/**
* Public key decryptor factory method.
* @param key the key that will work inside the decryptor
* @param eme determines the algorithm and encoding
* @return the public key decryptor object
*/
inline PK_Decryptor* get_pk_decryptor(const Private_Key& key,
                                      const std::string& eme)
   {
   return new PK_Decryptor_MR_with_EME(key, eme);
   }

/**
* Public key signer factory method.
* @param key the key that will work inside the signer
* @param emsa determines the algorithm, encoding and hash algorithm
* @param sig_format the signature format to be used
* @return the public key signer object
*/
inline PK_Signer* get_pk_signer(const Private_Key& key,
                                const std::string& emsa,
                                Signature_Format sig_format = IEEE_1363)
   {
   return new PK_Signer(key, emsa, sig_format);
   }

/**
* Public key verifier factory method.
* @param key the key that will work inside the verifier
* @param emsa determines the algorithm, encoding and hash algorithm
* @param sig_format the signature format to be used
* @return the public key verifier object
*/
inline PK_Verifier* get_pk_verifier(const Public_Key& key,
                                    const std::string& emsa,
                                    Signature_Format sig_format = IEEE_1363)
   {
   return new PK_Verifier(key, emsa, sig_format);
   }

/**
* Public key key agreement factory method.
* @param key the key that will work inside the key agreement
* @param kdf the kdf algorithm to use
* @return the key agreement algorithm
*/
inline PK_Key_Agreement* get_pk_kas(const PK_Key_Agreement_Key& key,
                                       const std::string& kdf)
   {
   return new PK_Key_Agreement(key, kdf);
   }

}

#endif
