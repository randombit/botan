/*
* PK Algorithm Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/look_pk.h>
#include <botan/lookup.h>

namespace Botan {

/*
* Get a PK_Encryptor object
*/
PK_Encryptor* get_pk_encryptor(const PK_Encrypting_Key& key,
                               const std::string& eme)
   {
   return new PK_Encryptor_MR_with_EME(key, get_eme(eme));
   }

/*
* Get a PK_Decryptor object
*/
PK_Decryptor* get_pk_decryptor(const PK_Decrypting_Key& key,
                               const std::string& eme)
   {
   return new PK_Decryptor_MR_with_EME(key, get_eme(eme));
   }

/*
* Get a PK_Signer object
*/
PK_Signer* get_pk_signer(const PK_Signing_Key& key,
                         const std::string& emsa,
                         Signature_Format sig_format)
   {
   PK_Signer* signer = new PK_Signer(key, get_emsa(emsa));
   signer->set_output_format(sig_format);
   return signer;
   }

/*
* Get a PK_Verifier object
*/
PK_Verifier* get_pk_verifier(const PK_Verifying_with_MR_Key& key,
                             const std::string& emsa,
                             Signature_Format sig_format)
   {
   PK_Verifier* verifier = new PK_Verifier_with_MR(key, get_emsa(emsa));
   verifier->set_input_format(sig_format);
   return verifier;
   }

/*
* Get a PK_Verifier object
*/
PK_Verifier* get_pk_verifier(const PK_Verifying_wo_MR_Key& key,
                             const std::string& emsa,
                             Signature_Format sig_format)
   {
   PK_Verifier* verifier = new PK_Verifier_wo_MR(key, get_emsa(emsa));
   verifier->set_input_format(sig_format);
   return verifier;
   }

/*
* Get a PK_Key_Agreement object
*/
PK_Key_Agreement* get_pk_kas(const PK_Key_Agreement_Key& key,
                             const std::string& kdf)
   {
   return new PK_Key_Agreement(key, get_kdf(kdf));
   }

}
