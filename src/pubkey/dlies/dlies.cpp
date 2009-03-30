/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/dlies.h>
#include <botan/look_pk.h>
#include <botan/xor_buf.h>

namespace Botan {

/*
* DLIES_Encryptor Constructor
*/
DLIES_Encryptor::DLIES_Encryptor(const PK_Key_Agreement_Key& k,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 u32bit mac_kl) :
   key(k), kdf(kdf_obj), mac(mac_obj), mac_keylen(mac_kl)
   {
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
   if(other_key.is_empty())
      throw Invalid_State("DLIES: The other key was never set");

   MemoryVector<byte> v = key.public_value();

   SecureVector<byte> out(v.size() + length + mac->OUTPUT_LENGTH);
   out.copy(v, v.size());
   out.copy(v.size(), in, length);

   SecureVector<byte> vz(v, key.derive_key(other_key, other_key.size()));

   const u32bit K_LENGTH = length + mac_keylen;
   OctetString K = kdf->derive_key(K_LENGTH, vz, vz.size());
   if(K.length() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   byte* C = out + v.size();

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
DLIES_Decryptor::DLIES_Decryptor(const PK_Key_Agreement_Key& k,
                                 KDF* kdf_obj,
                                 MessageAuthenticationCode* mac_obj,
                                 u32bit mac_kl) :
   key(k), kdf(kdf_obj), mac(mac_obj), mac_keylen(mac_kl)
   {
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
   const u32bit public_len = key.public_value().size();

   if(length < public_len + mac->OUTPUT_LENGTH)
      throw Decoding_Error("DLIES decryption: ciphertext is too short");

   const u32bit CIPHER_LEN = length - public_len - mac->OUTPUT_LENGTH;

   SecureVector<byte> v(msg, public_len);
   SecureVector<byte> C(msg + public_len, CIPHER_LEN);
   SecureVector<byte> T(msg + public_len + CIPHER_LEN, mac->OUTPUT_LENGTH);

   SecureVector<byte> vz(v, key.derive_key(v, v.size()));

   const u32bit K_LENGTH = C.size() + mac_keylen;
   OctetString K = kdf->derive_key(K_LENGTH, vz, vz.size());
   if(K.length() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");

   mac->set_key(K.begin(), mac_keylen);
   mac->update(C);
   for(u32bit j = 0; j != 8; ++j)
      mac->update(0);
   SecureVector<byte> T2 = mac->final();
   if(T != T2)
      throw Integrity_Failure("DLIES: message authentication failed");

   xor_buf(C, K.begin() + mac_keylen, C.size());

   return C;
   }

}
