/*************************************************
* PK Algorithm Lookup Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/look_pk.h>
#include <botan/lookup.h>

namespace Botan {

/*************************************************
* Get a PK_Encryptor object                      *
*************************************************/
std::auto_ptr<PK_Encryptor> get_pk_encryptor(const PK_Encrypting_Key& key,
                               const std::string& eme)
   {
   return std::auto_ptr<PK_Encryptor>(new PK_Encryptor_MR_with_EME(key, eme));
   }

/*************************************************
* Get a PK_Decryptor object                      *
*************************************************/
std::auto_ptr<PK_Decryptor> get_pk_decryptor(const PK_Decrypting_Key& key,
                               const std::string& eme)
   {
   return std::auto_ptr<PK_Decryptor>(new PK_Decryptor_MR_with_EME(key, eme));
   }

/*************************************************
* Get a PK_Signer object                         *
*************************************************/
std::auto_ptr<PK_Signer> get_pk_signer(const PK_Signing_Key& key,
                         const std::string& encoding,
                         Signature_Format sig_format)
   {
   std::auto_ptr<PK_Signer> signer(new PK_Signer(key, encoding));
   signer->set_output_format(sig_format);
   return signer;
   }

/*************************************************
* Get a PK_Verifier object                       *
*************************************************/
std::auto_ptr<PK_Verifier> get_pk_verifier(const PK_Verifying_with_MR_Key& key,
                             const std::string& encoding,
                             Signature_Format sig_format)
   {
   std::auto_ptr<PK_Verifier> verifier(new PK_Verifier_with_MR(key, encoding));
   verifier->set_input_format(sig_format);
   return verifier;
   }

/*************************************************
* Get a PK_Verifier object                       *
*************************************************/
std::auto_ptr<PK_Verifier> get_pk_verifier(const PK_Verifying_wo_MR_Key& key,
                             const std::string& encoding,
                             Signature_Format sig_format)
   {
   std::auto_ptr<PK_Verifier> verifier(new PK_Verifier_wo_MR(key, encoding));
   verifier->set_input_format(sig_format);
   return verifier;
   }

/*************************************************
* Get a PK_Key_Agreement object                  *
*************************************************/
std::auto_ptr<PK_Key_Agreement> get_pk_kas(const PK_Key_Agreement_Key& key,
                             const std::string& kdf)
   {
   return std::auto_ptr<PK_Key_Agreement>(new PK_Key_Agreement(key, kdf));
   }

}
