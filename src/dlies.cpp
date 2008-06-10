/*************************************************
* DLIES Source File                              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/dlies.h>
#include <botan/lookup.h>
#include <botan/look_pk.h>
#include <botan/bit_ops.h>
#include <memory>

namespace Botan {

/*************************************************
* DLIES_Encryptor Constructor                    *
*************************************************/
DLIES_Encryptor::DLIES_Encryptor(const PK_Key_Agreement_Key& k,
                                 const std::string& kdf,
                                 const std::string& mac, u32bit mk_len) :
   key(k), kdf_algo(kdf), mac_algo(mac), MAC_KEYLEN(mk_len)
   {
   }

/*************************************************
* DLIES Encryption                               *
*************************************************/
SecureVector<byte> DLIES_Encryptor::enc(const byte in[], u32bit length,
                                        RandomNumberGenerator&) const
   {
   if(length > maximum_input_size())
      throw Invalid_Argument("DLIES: Plaintext too large");
   if(other_key.is_empty())
      throw Invalid_State("DLIES: The other key was never set");

   std::auto_ptr<KDF> kdf(get_kdf(kdf_algo));
   std::auto_ptr<MessageAuthenticationCode> mac(get_mac(mac_algo));

   MemoryVector<byte> v = key.public_value();

   SecureVector<byte> out(v.size() + length + mac->OUTPUT_LENGTH);
   out.copy(v, v.size());
   out.copy(v.size(), in, length);

   SecureVector<byte> vz(v, key.derive_key(other_key, other_key.size()));

   const u32bit K_LENGTH = length + MAC_KEYLEN;
   OctetString K = kdf->derive_key(K_LENGTH, vz, vz.size());
   if(K.length() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");
   byte* C = out + v.size();

   xor_buf(C, K.begin() + MAC_KEYLEN, length);
   mac->set_key(K.begin(), MAC_KEYLEN);

   mac->update(C, length);
   for(u32bit j = 0; j != 8; ++j)
      mac->update(0);

   mac->final(C + length);

   return out;
   }

/*************************************************
* Set the other parties public key               *
*************************************************/
void DLIES_Encryptor::set_other_key(const MemoryRegion<byte>& ok)
   {
   other_key = ok;
   }

/*************************************************
* Return the max size, in bytes, of a message    *
*************************************************/
u32bit DLIES_Encryptor::maximum_input_size() const
   {
   return 32;
   }

/*************************************************
* DLIES_Decryptor Constructor                    *
*************************************************/
DLIES_Decryptor::DLIES_Decryptor(const PK_Key_Agreement_Key& k,
                                 const std::string& kdf,
                                 const std::string& mac, u32bit mk_len) :
   key(k), kdf_algo(kdf), mac_algo(mac),
   MAC_KEYLEN(mk_len), PUBLIC_LEN(key.public_value().size())
   {
   }

/*************************************************
* DLIES Decryption                               *
*************************************************/
SecureVector<byte> DLIES_Decryptor::dec(const byte msg[], u32bit length) const
   {
   std::auto_ptr<MessageAuthenticationCode> mac(get_mac(mac_algo));

   if(length < PUBLIC_LEN + mac->OUTPUT_LENGTH)
      throw Decoding_Error("DLIES decryption: ciphertext is too short");

   std::auto_ptr<KDF> kdf(get_kdf(kdf_algo));

   const u32bit CIPHER_LEN = length - PUBLIC_LEN - mac->OUTPUT_LENGTH;

   SecureVector<byte> v(msg, PUBLIC_LEN);
   SecureVector<byte> C(msg + PUBLIC_LEN, CIPHER_LEN);
   SecureVector<byte> T(msg + PUBLIC_LEN + CIPHER_LEN, mac->OUTPUT_LENGTH);

   SecureVector<byte> vz(v, key.derive_key(v, v.size()));

   const u32bit K_LENGTH = C.size() + MAC_KEYLEN;
   OctetString K = kdf->derive_key(K_LENGTH, vz, vz.size());
   if(K.length() != K_LENGTH)
      throw Encoding_Error("DLIES: KDF did not provide sufficient output");

   mac->set_key(K.begin(), MAC_KEYLEN);
   mac->update(C);
   for(u32bit j = 0; j != 8; ++j)
      mac->update(0);
   SecureVector<byte> T2 = mac->final();
   if(T != T2)
      throw Integrity_Failure("DLIES: message authentication failed");

   xor_buf(C, K.begin() + MAC_KEYLEN, C.size());

   return C;
   }

}
