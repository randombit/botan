/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dlies.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/*
* DLIES_Encryptor Constructor
*/
DLIES_Encryptor::DLIES_Encryptor(const PK_Key_Agreement_Key& key,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 size_t mac_kl) :
   m_ka(key, "Raw"),
   m_kdf(kdf_obj),
   m_mac(mac_obj),
   m_mac_keylen(mac_kl)
   {
   BOTAN_ASSERT_NONNULL(kdf_obj);
   BOTAN_ASSERT_NONNULL(mac_obj);
   m_my_key = key.public_value();
   }

/*
* DLIES Encryption
*/
std::vector<byte> DLIES_Encryptor::enc(const byte in[], size_t length,
                                       RandomNumberGenerator&) const
   {
   if(length > maximum_input_size())
      throw Invalid_Argument("DLIES: Plaintext too large");
   if(m_other_key.empty())
      throw Invalid_State("DLIES: The other key was never set");

   secure_vector<byte> out(m_my_key.size() + length + m_mac->output_length());
   buffer_insert(out, 0, m_my_key);
   buffer_insert(out, m_my_key.size(), in, length);

   secure_vector<byte> vz(m_my_key.begin(), m_my_key.end());
   vz += m_ka.derive_key(0, m_other_key).bits_of();

   const size_t K_LENGTH = length + m_mac_keylen;
   secure_vector<byte> K = m_kdf->derive_key(K_LENGTH, vz);

   if(K.size() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   byte* C = &out[m_my_key.size()];

   m_mac->set_key(K.data(), m_mac_keylen);
   xor_buf(C, &K[m_mac_keylen], length);

   m_mac->update(C, length);
   for(size_t j = 0; j != 8; ++j)
      m_mac->update(0);

   m_mac->final(C + length);

   return unlock(out);
   }

/*
* Set the other parties public key
*/
void DLIES_Encryptor::set_other_key(const std::vector<byte>& ok)
   {
   m_other_key = ok;
   }

/*
* Return the max size, in bytes, of a message
*/
size_t DLIES_Encryptor::maximum_input_size() const
   {
   return 32;
   }

/*
* DLIES_Decryptor Constructor
*/
DLIES_Decryptor::DLIES_Decryptor(const PK_Key_Agreement_Key& key,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 size_t mac_kl) :
   m_ka(key, "Raw"),
   m_kdf(kdf_obj),
   m_mac(mac_obj),
   m_mac_keylen(mac_kl)
   {
   m_my_key = key.public_value();
   }

/*
* DLIES Decryption
*/
secure_vector<byte> DLIES_Decryptor::do_decrypt(byte& valid_mask,
                                                const byte msg[], size_t length) const
   {
   if(length < m_my_key.size() + m_mac->output_length())
      throw Decoding_Error("DLIES decryption: ciphertext is too short");

   const size_t CIPHER_LEN = length - m_my_key.size() - m_mac->output_length();

   std::vector<byte> v(msg, msg + m_my_key.size());

   secure_vector<byte> C(msg + m_my_key.size(), msg + m_my_key.size() + CIPHER_LEN);

   secure_vector<byte> T(msg + m_my_key.size() + CIPHER_LEN,
                         msg + m_my_key.size() + CIPHER_LEN + m_mac->output_length());

   secure_vector<byte> vz(msg, msg + m_my_key.size());
   vz += m_ka.derive_key(0, v).bits_of();

   const size_t K_LENGTH = C.size() + m_mac_keylen;
   secure_vector<byte> K = m_kdf->derive_key(K_LENGTH, vz);
   if(K.size() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");

   m_mac->set_key(K.data(), m_mac_keylen);
   m_mac->update(C);
   for(size_t j = 0; j != 8; ++j)
      m_mac->update(0);
   secure_vector<byte> T2 = m_mac->final();

   valid_mask = CT::expand_mask<byte>(same_mem(T.data(), T2.data(), T.size()));

   xor_buf(C, K.data() + m_mac_keylen, C.size());

   return C;
   }

}
