/**
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mce_kem.h>
#include <botan/sha2_64.h>

namespace Botan {

McEliece_KEM_Encryptor::McEliece_KEM_Encryptor(const McEliece_PublicKey& public_key) :
   m_raw_pub_op(public_key, public_key.get_code_length())
   {
   }

std::pair<secure_vector<byte>, secure_vector<byte>>
McEliece_KEM_Encryptor::encrypt(RandomNumberGenerator& rng)
   {
   const McEliece_PublicKey& key = m_raw_pub_op.get_key();
   secure_vector<Botan::byte> plaintext((key.get_message_word_bit_length()+7)/8);
   rng.randomize(plaintext.data(), plaintext.size() );

   // unset unused bits in the last plaintext byte
   u32bit used = key.get_message_word_bit_length() % 8;
   if(used)
      {
      byte mask = (1 << used) - 1;
      plaintext[plaintext.size() - 1] &= mask;
      }

   secure_vector<gf2m> err_pos = create_random_error_positions(key.get_code_length(), key.get_t(), rng);

   mceliece_message_parts parts(err_pos, plaintext, key.get_code_length());
   secure_vector<Botan::byte> message_and_error_input = parts.get_concat();

   SHA_512 hash;
   hash.update(message_and_error_input);
   secure_vector<byte> sym_key = hash.final();
   secure_vector<byte> ciphertext = m_raw_pub_op.encrypt(message_and_error_input.data(),
                                                         message_and_error_input.size(), rng);

   return std::make_pair(ciphertext, sym_key);
   }


McEliece_KEM_Decryptor::McEliece_KEM_Decryptor(const McEliece_PrivateKey& mce_key) :
   m_raw_priv_op(mce_key)
   {
   }

secure_vector<Botan::byte> McEliece_KEM_Decryptor::decrypt(const byte msg[], size_t msg_len)
   {
   secure_vector<Botan::byte> message_and_error = m_raw_priv_op.decrypt(&msg[0], msg_len );

   SHA_512 hash;
   hash.update(message_and_error);

   secure_vector<byte> sym_key = hash.final();
   return sym_key;
   }

}
