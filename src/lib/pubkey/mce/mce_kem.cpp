/**
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mce_kem.h>
#include <botan/internal/mce_internal.h>
#include <botan/sha2_64.h>

namespace Botan {

McEliece_KEM_Encryptor::McEliece_KEM_Encryptor(const McEliece_PublicKey& public_key) :
   m_key(public_key)
   {
   }

std::pair<secure_vector<byte>, secure_vector<byte>>
McEliece_KEM_Encryptor::encrypt(RandomNumberGenerator& rng)
   {
   const secure_vector<byte> plaintext = m_key.random_plaintext_element(rng);

   secure_vector<byte> ciphertext, error_mask;
   mceliece_encrypt(ciphertext, error_mask, plaintext, m_key, rng);

   SHA_512 hash;
   hash.update(plaintext);
   hash.update(error_mask);
   secure_vector<byte> sym_key = hash.final();

   return std::make_pair(ciphertext, sym_key);
   }

McEliece_KEM_Decryptor::McEliece_KEM_Decryptor(const McEliece_PrivateKey& key) : m_key(key) { }

secure_vector<Botan::byte> McEliece_KEM_Decryptor::decrypt(const byte msg[], size_t msg_len)
   {
   secure_vector<byte> plaintext, error_mask;
   mceliece_decrypt(plaintext, error_mask, msg, msg_len, m_key);

   SHA_512 hash;
   hash.update(plaintext);
   hash.update(error_mask);

   secure_vector<byte> sym_key = hash.final();
   return sym_key;
   }

}
