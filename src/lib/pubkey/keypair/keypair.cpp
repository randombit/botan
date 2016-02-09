/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/keypair.h>
#include <botan/pubkey.h>

namespace Botan {

namespace KeyPair {

/*
* Check an encryption key pair for consistency
*/
bool encryption_consistency_check(RandomNumberGenerator& rng,
                                  const Private_Key& key,
                                  const std::string& padding)
   {
   PK_Encryptor_EME encryptor(key, padding);
   PK_Decryptor_EME decryptor(key, padding);

   /*
   Weird corner case, if the key is too small to encrypt anything at
   all. This can happen with very small RSA keys with PSS
   */
   if(encryptor.maximum_input_size() == 0)
      return true;

   std::vector<byte> plaintext =
      unlock(rng.random_vec(encryptor.maximum_input_size() - 1));

   std::vector<byte> ciphertext = encryptor.encrypt(plaintext, rng);
   if(ciphertext == plaintext)
      return false;

   std::vector<byte> decrypted = unlock(decryptor.decrypt(ciphertext));

   return (plaintext == decrypted);
   }

/*
* Check a signature key pair for consistency
*/
bool signature_consistency_check(RandomNumberGenerator& rng,
                                 const Private_Key& key,
                                 const std::string& padding)
   {
   PK_Signer signer(key, padding);
   PK_Verifier verifier(key, padding);

   std::vector<byte> message = unlock(rng.random_vec(16));

   std::vector<byte> signature;

   try
      {
      signature = signer.sign_message(message, rng);
      }
   catch(Encoding_Error&)
      {
      return false;
      }

   if(!verifier.verify_message(message, signature))
      return false;

   // Now try to check a corrupt signature, ensure it does not succeed
   ++message[0];

   if(verifier.verify_message(message, signature))
      return false;

   return true;
   }

}

}
