/*************************************************
* Keypair Checks Source File                     *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/keypair.h>
#include <botan/look_pk.h>
#include <botan/rng.h>
#include <memory>

namespace Botan {

namespace KeyPair {

/*************************************************
* Check an encryption key pair for consistency   *
*************************************************/
void check_key(PK_Encryptor* encryptor, PK_Decryptor* decryptor)
   {
   if(encryptor->maximum_input_size() == 0)
      return;

   std::auto_ptr<PK_Encryptor> enc(encryptor);
   std::auto_ptr<PK_Decryptor> dec(decryptor);

   SecureVector<byte> message(enc->maximum_input_size() - 1);
   Global_RNG::randomize(message, message.size());

   SecureVector<byte> ciphertext = enc->encrypt(message);
   if(ciphertext == message)
      throw Self_Test_Failure("Encryption key pair consistency failure");

   SecureVector<byte> message2 = dec->decrypt(ciphertext);
   if(message != message2)
      throw Self_Test_Failure("Encryption key pair consistency failure");
   }

/*************************************************
* Check a signature key pair for consistency     *
*************************************************/
void check_key(PK_Signer* signer, PK_Verifier* verifier)
   {
   std::auto_ptr<PK_Signer> sig(signer);
   std::auto_ptr<PK_Verifier> ver(verifier);

   SecureVector<byte> message(16);
   Global_RNG::randomize(message, message.size());

   SecureVector<byte> signature;

   try {
      signature = sig->sign_message(message);
   }
   catch(Encoding_Error)
      {
      return;
      }

   if(!ver->verify_message(message, signature))
      throw Self_Test_Failure("Signature key pair consistency failure");

   ++message[0];
   if(ver->verify_message(message, signature))
      throw Self_Test_Failure("Signature key pair consistency failure");
   }

}

}
