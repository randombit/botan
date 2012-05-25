/*
* PK Filters
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pk_filts.h>

namespace Botan {

/*
* Append to the buffer
*/
void PK_Encryptor_Filter::write(const byte input[], size_t length)
   {
   buffer += std::make_pair(input, length);
   }

/*
* Encrypt the message
*/
void PK_Encryptor_Filter::end_msg()
   {
   send(cipher->encrypt(buffer, rng));
   buffer.clear();
   }

/*
* Append to the buffer
*/
void PK_Decryptor_Filter::write(const byte input[], size_t length)
   {
   buffer += std::make_pair(input, length);
   }

/*
* Decrypt the message
*/
void PK_Decryptor_Filter::end_msg()
   {
   send(cipher->decrypt(buffer));
   buffer.clear();
   }

/*
* Add more data
*/
void PK_Signer_Filter::write(const byte input[], size_t length)
   {
   signer->update(input, length);
   }

/*
* Sign the message
*/
void PK_Signer_Filter::end_msg()
   {
   send(signer->signature(rng));
   }

/*
* Add more data
*/
void PK_Verifier_Filter::write(const byte input[], size_t length)
   {
   verifier->update(input, length);
   }

/*
* Verify the message
*/
void PK_Verifier_Filter::end_msg()
   {
   if(signature.empty())
      throw Invalid_State("PK_Verifier_Filter: No signature to check against");
   bool is_valid = verifier->check_signature(signature);
   send((is_valid ? 1 : 0));
   }

/*
* Set the signature to check
*/
void PK_Verifier_Filter::set_signature(const byte sig[], size_t length)
   {
   signature.assign(sig, sig + length);
   }

/*
* Set the signature to check
*/
void PK_Verifier_Filter::set_signature(const secure_vector<byte>& sig)
   {
   signature = sig;
   }

/*
* PK_Verifier_Filter Constructor
*/
PK_Verifier_Filter::PK_Verifier_Filter(PK_Verifier* v, const byte sig[],
                                       size_t length) :
   verifier(v), signature(sig, sig + length)
   {
   }

/*
* PK_Verifier_Filter Constructor
*/
PK_Verifier_Filter::PK_Verifier_Filter(PK_Verifier* v,
                                       const secure_vector<byte>& sig) :
   verifier(v), signature(sig)
   {
   }

}
