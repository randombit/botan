/*
* Keypair Checks
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/keypair.h>
#include <botan/pubkey.h>
#include <botan/rng.h>

namespace Botan {

namespace KeyPair {

/*
* Check an encryption key pair for consistency
*/
bool encryption_consistency_check(RandomNumberGenerator& rng,
                                  const Private_Key& private_key,
                                  const Public_Key& public_key,
                                  const std::string& padding)
   {
   PK_Encryptor_EME encryptor(public_key, rng, padding);
   PK_Decryptor_EME decryptor(private_key, rng, padding);

   /*
   Weird corner case, if the key is too small to encrypt anything at
   all. This can happen with very small RSA keys with PSS
   */
   if(encryptor.maximum_input_size() == 0)
      return true;

   std::vector<uint8_t> plaintext;
   rng.random_vec(plaintext, encryptor.maximum_input_size() - 1);

   std::vector<uint8_t> ciphertext = encryptor.encrypt(plaintext, rng);
   if(ciphertext == plaintext)
      return false;

   std::vector<uint8_t> decrypted = unlock(decryptor.decrypt(ciphertext));

   return (plaintext == decrypted);
   }

/*
* Check a signature key pair for consistency
*/
bool signature_consistency_check(RandomNumberGenerator& rng,
                                 const Private_Key& private_key,
                                 const Public_Key& public_key,
                                 const std::string& padding)
   {
   PK_Signer signer(private_key, rng, padding);
   PK_Verifier verifier(public_key, padding);

   std::vector<uint8_t> message(32);
   rng.randomize(message.data(), message.size());

   std::vector<uint8_t> signature;

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
   ++signature[0];

   if(verifier.verify_message(message, signature))
      return false;

   return true;
   }

}

}
