/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dlies.h>

namespace Botan {

/*
* DLIES_Encryptor Constructor
*/
DLIES_Encryptor::DLIES_Encryptor(const PK_Key_Agreement_Key& key,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 size_t mac_kl) :
   ka(key, "Raw"),
   kdf(kdf_obj),
   mac(mac_obj),
   mac_keylen(mac_kl)
   {
   my_key = key.public_value();
   }

/*
* DLIES Encryption
*/
std::vector<byte> DLIES_Encryptor::enc(const byte in[], size_t length,
                                       RandomNumberGenerator&) const
   {
   if(length > maximum_input_size())
      throw Invalid_Argument("DLIES: Plaintext too large");
   if(other_key.empty())
      throw Invalid_State("DLIES: The other key was never set");

   secure_vector<byte> out(my_key.size() + length + mac->output_length());
   buffer_insert(out, 0, my_key);
   buffer_insert(out, my_key.size(), in, length);

   secure_vector<byte> vz(my_key.begin(), my_key.end());
   vz += ka.derive_key(0, other_key).bits_of();

   const size_t K_LENGTH = length + mac_keylen;
   secure_vector<byte> K = kdf->derive_key(K_LENGTH, vz);

   if(K.size() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   byte* C = &out[my_key.size()];

   mac->set_key(K.data(), mac_keylen);
   xor_buf(C, &K[mac_keylen], length);

   mac->update(C, length);
   for(size_t j = 0; j != 8; ++j)
      mac->update(0);

   mac->final(C + length);

   return unlock(out);
   }

/*
* Set the other parties public key
*/
void DLIES_Encryptor::set_other_key(const std::vector<byte>& ok)
   {
   other_key = ok;
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
   ka(key, "Raw"),
   kdf(kdf_obj),
   mac(mac_obj),
   mac_keylen(mac_kl)
   {
   my_key = key.public_value();
   }

/*
* DLIES Decryption
*/
secure_vector<byte> DLIES_Decryptor::dec(const byte msg[], size_t length) const
   {
   if(length < my_key.size() + mac->output_length())
      throw Decoding_Error("DLIES decryption: ciphertext is too short");

   const size_t CIPHER_LEN = length - my_key.size() - mac->output_length();

   std::vector<byte> v(msg, msg + my_key.size());

   secure_vector<byte> C(msg + my_key.size(), msg + my_key.size() + CIPHER_LEN);

   secure_vector<byte> T(msg + my_key.size() + CIPHER_LEN,
                         msg + my_key.size() + CIPHER_LEN + mac->output_length());

   secure_vector<byte> vz(msg, msg + my_key.size());
   vz += ka.derive_key(0, v).bits_of();

   const size_t K_LENGTH = C.size() + mac_keylen;
   secure_vector<byte> K = kdf->derive_key(K_LENGTH, vz);
   if(K.size() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");

   mac->set_key(K.data(), mac_keylen);
   mac->update(C);
   for(size_t j = 0; j != 8; ++j)
      mac->update(0);
   secure_vector<byte> T2 = mac->final();
   if(T != T2)
      throw Decoding_Error("DLIES: message authentication failed");

   xor_buf(C, K.data() + mac_keylen, C.size());

   return C;
   }

}
