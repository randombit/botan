/*
* PK Algorithm Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PK_LOOKUP_H__
#define BOTAN_PK_LOOKUP_H__

#include <botan/build.h>
#include <botan/pubkey.h>

namespace Botan {

/**
* Public key encryptor factory method.
* @param key the key that will work inside the encryptor
* @param pad determines the algorithm and encoding
* @return the public key encryptor object
*/
BOTAN_DLL PK_Encryptor* get_pk_encryptor(const PK_Encrypting_Key& key,
                                         const std::string& pad);

/**
* Public key decryptor factory method.
* @param key the key that will work inside the decryptor
* @param pad determines the algorithm and encoding
* @return the public key decryptor object
*/
BOTAN_DLL PK_Decryptor* get_pk_decryptor(const PK_Decrypting_Key& key,
                                         const std::string& pad);

/**
* Public key signer factory method.
* @param key the key that will work inside the signer
* @param pad determines the algorithm, encoding and hash algorithm
* @param sig_format the signature format to be used
* @return the public key signer object
*/
BOTAN_DLL PK_Signer* get_pk_signer(const PK_Signing_Key& key,
                                   const std::string& pad,
                                   Signature_Format = IEEE_1363);

/**
* Public key verifier factory method.
* @param key the key that will work inside the verifier
* @param pad determines the algorithm, encoding and hash algorithm
* @param sig_format the signature format to be used
* @return the public key verifier object
*/
BOTAN_DLL PK_Verifier* get_pk_verifier(const PK_Verifying_with_MR_Key& key,
                                       const std::string& pad,
                                       Signature_Format = IEEE_1363);

/**
* Public key verifier factory method.
* @param key the key that will work inside the verifier
* @param pad determines the algorithm, encoding and hash algorithm
* @param sig_form the signature format to be used
* @return the public key verifier object
*/
BOTAN_DLL PK_Verifier* get_pk_verifier(const PK_Verifying_wo_MR_Key& key,
                                       const std::string& pad,
                                       Signature_Format sig_form = IEEE_1363);

/**
* Public key key agreement factory method.
* @param key the key that will work inside the key agreement
* @param pad determines the algorithm, encoding and hash algorithm
* @return the public key verifier object
*/
BOTAN_DLL PK_Key_Agreement* get_pk_kas(const PK_Key_Agreement_Key& key,
                                       const std::string& pad);

}

#endif
