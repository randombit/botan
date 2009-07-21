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
void PK_Encryptor_Filter::write(const byte input[], u32bit length)
   {
   buffer.append(input, length);
   }

/*
* Encrypt the message
*/
void PK_Encryptor_Filter::end_msg()
   {
   send(cipher->encrypt(buffer, buffer.size(), rng));
   buffer.destroy();
   }

/*
* Append to the buffer
*/
void PK_Decryptor_Filter::write(const byte input[], u32bit length)
   {
   buffer.append(input, length);
   }

/*
* Decrypt the message
*/
void PK_Decryptor_Filter::end_msg()
   {
   send(cipher->decrypt(buffer, buffer.size()));
   buffer.destroy();
   }

/*
* Add more data
*/
void PK_Signer_Filter::write(const byte input[], u32bit length)
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
void PK_Verifier_Filter::write(const byte input[], u32bit length)
   {
   verifier->update(input, length);
   }

/*
* Verify the message
*/
void PK_Verifier_Filter::end_msg()
   {
   if(signature.is_empty())
      throw Exception("PK_Verifier_Filter: No signature to check against");
   bool is_valid = verifier->check_signature(signature, signature.size());
   send((is_valid ? 1 : 0));
   }

/*
* Set the signature to check
*/
void PK_Verifier_Filter::set_signature(const byte sig[], u32bit length)
   {
   signature.set(sig, length);
   }

/*
* Set the signature to check
*/
void PK_Verifier_Filter::set_signature(const MemoryRegion<byte>& sig)
   {
   signature = sig;
   }

/*
* PK_Verifier_Filter Constructor
*/
PK_Verifier_Filter::PK_Verifier_Filter(PK_Verifier* v, const byte sig[],
                                       u32bit length) :
   verifier(v), signature(sig, length)
   {
   }

/*
* PK_Verifier_Filter Constructor
*/
PK_Verifier_Filter::PK_Verifier_Filter(PK_Verifier* v,
                                       const MemoryRegion<byte>& sig) :
   verifier(v), signature(sig)
   {
   }

}
