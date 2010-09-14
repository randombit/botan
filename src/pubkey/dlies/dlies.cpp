/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dlies.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* DLIES_Encryptor Constructor
*/
DLIES_Encryptor::DLIES_Encryptor(const PK_Key_Agreement_Key& key,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 u32bit mac_kl) :
   ka(key, "Raw"),
   kdf(kdf_obj),
   mac(mac_obj),
   mac_keylen(mac_kl)
   {
   my_key = key.public_value();
   }

DLIES_Encryptor::~DLIES_Encryptor()
   {
   delete kdf;
   delete mac;
   }

/*
* DLIES Encryption
*/
SecureVector<byte> DLIES_Encryptor::enc(const byte in[], u32bit length,
                                        RandomNumberGenerator&) const
   {
   if(length > maximum_input_size())
      throw Invalid_Argument("DLIES: Plaintext too large");
   if(other_key.empty())
      throw Invalid_State("DLIES: The other key was never set");

   SecureVector<byte> out(my_key.size() + length + mac->OUTPUT_LENGTH);
   out.copy(&my_key[0], my_key.size());
   out.copy(my_key.size(), in, length);

   SecureVector<byte> vz = my_key;
   vz.append(ka.derive_key(0, other_key).bits_of());

   const u32bit K_LENGTH = length + mac_keylen;
   OctetString K = kdf->derive_key(K_LENGTH, vz);

   if(K.length() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   byte* C = &out[my_key.size()];

   xor_buf(C, K.begin() + mac_keylen, length);
   mac->set_key(K.begin(), mac_keylen);

   mac->update(C, length);
   for(u32bit j = 0; j != 8; ++j)
      mac->update(0);

   mac->final(C + length);

   return out;
   }

/*
* Set the other parties public key
*/
void DLIES_Encryptor::set_other_key(const MemoryRegion<byte>& ok)
   {
   other_key = ok;
   }

/*
* Return the max size, in bytes, of a message
*/
u32bit DLIES_Encryptor::maximum_input_size() const
   {
   return 32;
   }

/*
* DLIES_Decryptor Constructor
*/
DLIES_Decryptor::DLIES_Decryptor(const PK_Key_Agreement_Key& key,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 u32bit mac_kl) :
   ka(key, "Raw"),
   kdf(kdf_obj),
   mac(mac_obj),
   mac_keylen(mac_kl)
   {
   my_key = key.public_value();
   }

DLIES_Decryptor::~DLIES_Decryptor()
   {
   delete kdf;
   delete mac;
   }

/*
* DLIES Decryption
*/
SecureVector<byte> DLIES_Decryptor::dec(const byte msg[], u32bit length) const
   {
   if(length < my_key.size() + mac->OUTPUT_LENGTH)
      throw Decoding_Error("DLIES decryption: ciphertext is too short");

   const u32bit CIPHER_LEN = length - my_key.size() - mac->OUTPUT_LENGTH;

   SecureVector<byte> v(msg, my_key.size());
   SecureVector<byte> C(msg + my_key.size(), CIPHER_LEN);
   SecureVector<byte> T(msg + my_key.size() + CIPHER_LEN, mac->OUTPUT_LENGTH);

   SecureVector<byte> vz(msg, my_key.size());
   vz.append(ka.derive_key(0, v).bits_of());

   const u32bit K_LENGTH = C.size() + mac_keylen;
   OctetString K = kdf->derive_key(K_LENGTH, vz);
   if(K.length() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");

   mac->set_key(K.begin(), mac_keylen);
   mac->update(C);
   for(u32bit j = 0; j != 8; ++j)
      mac->update(0);
   SecureVector<byte> T2 = mac->final();
   if(T != T2)
      throw Decoding_Error("DLIES: message authentication failed");

   xor_buf(C, K.begin() + mac_keylen, C.size());

   return C;
   }

}
