/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/keypair.h>

namespace Botan {

namespace KeyPair {

/*
* Check an encryption key pair for consistency
*/
void check_key(RandomNumberGenerator& rng,
               PK_Encryptor& encryptor,
               PK_Decryptor& decryptor)
   {
   if(encryptor.maximum_input_size() == 0)
      return;

   SecureVector<byte> message(encryptor.maximum_input_size() - 1);
   rng.randomize(message, message.size());

   SecureVector<byte> ciphertext = encryptor.encrypt(message, rng);
   if(ciphertext == message)
      throw Self_Test_Failure("Encryption key pair consistency failure");

   SecureVector<byte> message2 = decryptor.decrypt(ciphertext);
   if(message != message2)
      throw Self_Test_Failure("Encryption key pair consistency failure");
   }

/*
* Check a signature key pair for consistency
*/
void check_key(RandomNumberGenerator& rng,
               PK_Signer& signer,
               PK_Verifier& verifier)
   {
   SecureVector<byte> message(16);
   rng.randomize(message, message.size());

   SecureVector<byte> signature;

   try
      {
      signature = signer.sign_message(message, rng);
      }
   catch(Encoding_Error)
      {
      return;
      }

   if(!verifier.verify_message(message, signature))
      throw Self_Test_Failure("Signature key pair consistency failure");

   ++message[0];
   if(verifier.verify_message(message, signature))
      throw Self_Test_Failure("Signature key pair consistency failure");
   }

}

}
