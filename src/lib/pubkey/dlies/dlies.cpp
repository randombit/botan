/*
* DLIES
* (C) 1999-2007 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dlies.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

DLIES_Encryptor::DLIES_Encryptor(const DH_PrivateKey& own_priv_key,
                                 KDF* kdf,
                                 MessageAuthenticationCode* mac,
                                 size_t mac_key_length) :
   DLIES_Encryptor(own_priv_key, kdf, nullptr, 0, mac, mac_key_length)
   {
   }

DLIES_Encryptor::DLIES_Encryptor(const DH_PrivateKey& own_priv_key,
                                 KDF* kdf,
                                 Cipher_Mode* cipher,
                                 size_t cipher_key_len,
                                 MessageAuthenticationCode* mac,
                                 size_t mac_key_length) :
   m_other_pub_key(),
   m_own_pub_key(own_priv_key.public_value()),
   m_ka(own_priv_key, "Raw"),
   m_kdf(kdf),
   m_cipher(cipher),
   m_cipher_key_len(cipher_key_len),
   m_mac(mac),
   m_mac_keylen(mac_key_length),
   m_iv()
   {
   BOTAN_ASSERT_NONNULL(kdf);
   BOTAN_ASSERT_NONNULL(mac);
   }

std::vector<byte> DLIES_Encryptor::enc(const byte in[], size_t length,
                                       RandomNumberGenerator&) const
   {
   if(m_other_pub_key.empty())
      {
      throw Invalid_State("DLIES: The other key was never set");
      }

   // calculate secret value
   const SymmetricKey secret_value = m_ka.derive_key(0, m_other_pub_key);

   // derive secret key from secret value
   const size_t required_key_length = m_cipher ? m_cipher_key_len + m_mac_keylen : length + m_mac_keylen;
   const secure_vector<byte> secret_keys = m_kdf->derive_key(required_key_length, secret_value.bits_of());

   if(secret_keys.size() != required_key_length)
      {
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
      }

   secure_vector<byte> ciphertext(in, in + length);
   const size_t cipher_key_len = m_cipher ? m_cipher_key_len : length;

   if(m_cipher)
      {
      SymmetricKey enc_key(secret_keys.data(), cipher_key_len);
      m_cipher->set_key(enc_key);

      if(m_iv.size())
         {
         m_cipher->start(m_iv.bits_of());
         }

      m_cipher->finish(ciphertext);
      }
   else
      {
      xor_buf(ciphertext, secret_keys, cipher_key_len);
      }

   // calculate MAC
   m_mac->set_key(secret_keys.data() + cipher_key_len, m_mac_keylen);
   secure_vector<byte> tag = m_mac->process(ciphertext);

   // out = (ephemeral) public key + ciphertext + tag
   secure_vector<byte> out(m_own_pub_key.size() + ciphertext.size() + tag.size());
   buffer_insert(out, 0, m_own_pub_key);
   buffer_insert(out, 0 + m_own_pub_key.size(), ciphertext);
   buffer_insert(out, 0 + m_own_pub_key.size() + ciphertext.size(), tag);

   return unlock(out);
   }

/**
* Return the max size, in bytes, of a message
* Not_Implemented if DLIES is used in XOR encryption mode
*/
size_t DLIES_Encryptor::maximum_input_size() const
   {
   if(m_cipher)
      {
      // no limit in block cipher mode
      return std::numeric_limits<size_t>::max();
      }
   else
      {
      // No way to determine if the KDF will output enough bits for XORing with the plaintext?!
      throw Not_Implemented("Not implemented for XOR encryption mode");
      }
   }

DLIES_Decryptor::DLIES_Decryptor(const DH_PrivateKey& own_priv_key,
                                 KDF* kdf,
                                 Cipher_Mode* cipher,
                                 size_t cipher_key_len,
                                 MessageAuthenticationCode* mac,
                                 size_t mac_key_length) :
   m_pub_key_size(own_priv_key.public_value().size()),
   m_ka(own_priv_key, "Raw"),
   m_kdf(kdf),
   m_cipher(cipher),
   m_cipher_key_len(cipher_key_len),
   m_mac(mac),
   m_mac_keylen(mac_key_length),
   m_iv()
   {
   BOTAN_ASSERT_NONNULL(kdf);
   BOTAN_ASSERT_NONNULL(mac);
   }

DLIES_Decryptor::DLIES_Decryptor(const DH_PrivateKey& own_priv_key,
                                 KDF* kdf,
                                 MessageAuthenticationCode* mac,
                                 size_t mac_key_length) :
   DLIES_Decryptor(own_priv_key, kdf, nullptr, 0, mac, mac_key_length)
   {}

secure_vector<byte> DLIES_Decryptor::do_decrypt(byte& valid_mask,
      const byte msg[], size_t length) const
   {
   if(length < m_pub_key_size + m_mac->output_length())
      {
      throw Decoding_Error("DLIES decryption: ciphertext is too short");
      }

   // calculate secret value
   std::vector<byte> other_pub_key(msg, msg + m_pub_key_size);
   const SymmetricKey secret_value = m_ka.derive_key(0, other_pub_key);

   const size_t ciphertext_len = length - m_pub_key_size - m_mac->output_length();
   size_t cipher_key_len = m_cipher ? m_cipher_key_len : ciphertext_len;

   // derive secret key from secret value
   const size_t required_key_length = cipher_key_len + m_mac_keylen;
   secure_vector<byte> secret_keys = m_kdf->derive_key(required_key_length, secret_value.bits_of());

   if(secret_keys.size() != required_key_length)
      {
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
      }

   secure_vector<byte> ciphertext(msg + m_pub_key_size, msg + m_pub_key_size + ciphertext_len);

   // calculate MAC
   m_mac->set_key(secret_keys.data() + cipher_key_len, m_mac_keylen);
   secure_vector<byte> calculated_tag = m_mac->process(ciphertext);

   // calculated tag == received tag ?
   secure_vector<byte> tag(msg + m_pub_key_size + ciphertext_len,
                           msg + m_pub_key_size + ciphertext_len + m_mac->output_length());

   valid_mask = CT::expand_mask<byte>(same_mem(tag.data(), calculated_tag.data(), tag.size()));

   // decrypt
   if(m_cipher)
      {
      if(valid_mask)
         {
         SymmetricKey dec_key(secret_keys.data(), cipher_key_len);
         m_cipher->set_key(dec_key);

         try
            {
            // the decryption can fail:
            // e.g. Integrity_Failure is thrown if GCM is used and the message does not have a valid tag

            if(m_iv.size())
               {
               m_cipher->start(m_iv.bits_of());
               }

            m_cipher->finish(ciphertext);
            }
         catch(...)
            {
            valid_mask = 0;
            }

         }
      else
         {
         return secure_vector<byte>();
         }
      }
   else
      {
      xor_buf(ciphertext, secret_keys.data(), cipher_key_len);
      }

   return ciphertext;
   }

}
