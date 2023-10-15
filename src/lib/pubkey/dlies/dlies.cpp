/*
* DLIES
* (C) 1999-2007 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dlies.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/stl_util.h>
#include <limits>

namespace Botan {

DLIES_Encryptor::DLIES_Encryptor(const DH_PrivateKey& own_priv_key,
                                 RandomNumberGenerator& rng,
                                 std::unique_ptr<KDF> kdf,
                                 std::unique_ptr<MessageAuthenticationCode> mac,
                                 size_t mac_key_length) :
      DLIES_Encryptor(own_priv_key, rng, std::move(kdf), nullptr, 0, std::move(mac), mac_key_length) {}

DLIES_Encryptor::DLIES_Encryptor(const DH_PrivateKey& own_priv_key,
                                 RandomNumberGenerator& rng,
                                 std::unique_ptr<KDF> kdf,
                                 std::unique_ptr<Cipher_Mode> cipher,
                                 size_t cipher_key_len,
                                 std::unique_ptr<MessageAuthenticationCode> mac,
                                 size_t mac_key_length) :
      m_other_pub_key(),
      m_own_pub_key(own_priv_key.public_value()),
      m_ka(own_priv_key, rng, "Raw"),
      m_kdf(std::move(kdf)),
      m_cipher(std::move(cipher)),
      m_cipher_key_len(cipher_key_len),
      m_mac(std::move(mac)),
      m_mac_keylen(mac_key_length),
      m_iv() {
   BOTAN_ASSERT_NONNULL(m_kdf);
   BOTAN_ASSERT_NONNULL(m_mac);
}

std::vector<uint8_t> DLIES_Encryptor::enc(const uint8_t in[], size_t length, RandomNumberGenerator& /*unused*/) const {
   if(m_other_pub_key.empty()) {
      throw Invalid_State("DLIES: The other key was never set");
   }

   // calculate secret value
   const SymmetricKey secret_value = m_ka.derive_key(0, m_other_pub_key);

   // derive secret key from secret value
   const size_t required_key_length = m_cipher ? m_cipher_key_len + m_mac_keylen : length + m_mac_keylen;
   const secure_vector<uint8_t> secret_keys = m_kdf->derive_key(required_key_length, secret_value.bits_of());

   if(secret_keys.size() != required_key_length) {
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   }

   secure_vector<uint8_t> ciphertext(in, in + length);
   const size_t cipher_key_len = m_cipher ? m_cipher_key_len : length;

   if(m_cipher) {
      SymmetricKey enc_key(secret_keys.data(), cipher_key_len);
      m_cipher->set_key(enc_key);

      if(m_iv.empty() && !m_cipher->valid_nonce_length(m_iv.size())) {
         throw Invalid_Argument("DLIES with " + m_cipher->name() + " requires an IV be set");
      }
      m_cipher->start(m_iv.bits_of());
      m_cipher->finish(ciphertext);
   } else {
      xor_buf(ciphertext, secret_keys, cipher_key_len);
   }

   // calculate MAC
   m_mac->set_key(secret_keys.data() + cipher_key_len, m_mac_keylen);
   const auto tag = m_mac->process(ciphertext);

   // out = (ephemeral) public key + ciphertext + tag
   return concat(m_own_pub_key, ciphertext, tag);
}

/**
* Return the max size, in bytes, of a message
* We assume DLIES is only used for key transport and limit the maximum size
* to 512 bits
*/
size_t DLIES_Encryptor::maximum_input_size() const {
   return 64;
}

size_t DLIES_Encryptor::ciphertext_length(size_t ptext_len) const {
   return m_own_pub_key.size() + m_mac->output_length() + m_cipher->output_length(ptext_len);
}

DLIES_Decryptor::DLIES_Decryptor(const DH_PrivateKey& own_priv_key,
                                 RandomNumberGenerator& rng,
                                 std::unique_ptr<KDF> kdf,
                                 std::unique_ptr<Cipher_Mode> cipher,
                                 size_t cipher_key_len,
                                 std::unique_ptr<MessageAuthenticationCode> mac,
                                 size_t mac_key_length) :
      m_pub_key_size(own_priv_key.public_value().size()),
      m_ka(own_priv_key, rng, "Raw"),
      m_kdf(std::move(kdf)),
      m_cipher(std::move(cipher)),
      m_cipher_key_len(cipher_key_len),
      m_mac(std::move(mac)),
      m_mac_keylen(mac_key_length),
      m_iv() {
   BOTAN_ASSERT_NONNULL(m_kdf);
   BOTAN_ASSERT_NONNULL(m_mac);
}

DLIES_Decryptor::DLIES_Decryptor(const DH_PrivateKey& own_priv_key,
                                 RandomNumberGenerator& rng,
                                 std::unique_ptr<KDF> kdf,
                                 std::unique_ptr<MessageAuthenticationCode> mac,
                                 size_t mac_key_length) :
      DLIES_Decryptor(own_priv_key, rng, std::move(kdf), nullptr, 0, std::move(mac), mac_key_length) {}

size_t DLIES_Decryptor::plaintext_length(size_t ctext_len) const {
   if(ctext_len < m_pub_key_size + m_mac->output_length()) {
      return 0;  // will throw if attempted
   }

   return ctext_len - (m_pub_key_size + m_mac->output_length());
}

secure_vector<uint8_t> DLIES_Decryptor::do_decrypt(uint8_t& valid_mask, const uint8_t msg[], size_t length) const {
   if(length < m_pub_key_size + m_mac->output_length()) {
      throw Decoding_Error("DLIES decryption: ciphertext is too short");
   }

   // calculate secret value
   std::vector<uint8_t> other_pub_key(msg, msg + m_pub_key_size);
   const SymmetricKey secret_value = m_ka.derive_key(0, other_pub_key);

   const size_t ciphertext_len = length - m_pub_key_size - m_mac->output_length();
   size_t cipher_key_len = m_cipher ? m_cipher_key_len : ciphertext_len;

   // derive secret key from secret value
   const size_t required_key_length = cipher_key_len + m_mac_keylen;
   secure_vector<uint8_t> secret_keys = m_kdf->derive_key(required_key_length, secret_value.bits_of());

   if(secret_keys.size() != required_key_length) {
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   }

   secure_vector<uint8_t> ciphertext(msg + m_pub_key_size, msg + m_pub_key_size + ciphertext_len);

   // calculate MAC
   m_mac->set_key(secret_keys.data() + cipher_key_len, m_mac_keylen);
   secure_vector<uint8_t> calculated_tag = m_mac->process(ciphertext);

   // calculated tag == received tag ?
   secure_vector<uint8_t> tag(msg + m_pub_key_size + ciphertext_len,
                              msg + m_pub_key_size + ciphertext_len + m_mac->output_length());

   valid_mask = CT::is_equal(tag.data(), calculated_tag.data(), tag.size()).value();

   // decrypt
   if(m_cipher) {
      if(valid_mask) {
         SymmetricKey dec_key(secret_keys.data(), cipher_key_len);
         m_cipher->set_key(dec_key);

         try {
            // the decryption can fail:
            // e.g. Invalid_Authentication_Tag is thrown if GCM is used and the message does not have a valid tag

            if(m_iv.empty() && !m_cipher->valid_nonce_length(m_iv.size())) {
               throw Invalid_Argument("DLIES with " + m_cipher->name() + " requires an IV be set");
            }
            m_cipher->start(m_iv.bits_of());
            m_cipher->finish(ciphertext);
         } catch(...) {
            valid_mask = 0;
         }

      } else {
         return secure_vector<uint8_t>();
      }
   } else {
      xor_buf(ciphertext, secret_keys.data(), cipher_key_len);
   }

   return ciphertext;
}

}  // namespace Botan
