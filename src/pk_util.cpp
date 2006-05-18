/*************************************************
* PK Utility Classes Source File                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* Encode a message                               *
*************************************************/
SecureVector<byte> EME::encode(const byte msg[], u32bit msg_len,
                               u32bit key_bits) const
   {
   return pad(msg, msg_len, key_bits);
   }

/*************************************************
* Encode a message                               *
*************************************************/
SecureVector<byte> EME::encode(const MemoryRegion<byte>& msg,
                               u32bit key_bits) const
   {
   return pad(msg, msg.size(), key_bits);
   }

/*************************************************
* Decode a message                               *
*************************************************/
SecureVector<byte> EME::decode(const byte msg[], u32bit msg_len,
                               u32bit key_bits) const
   {
   return unpad(msg, msg_len, key_bits);
   }

/*************************************************
* Decode a message                               *
*************************************************/
SecureVector<byte> EME::decode(const MemoryRegion<byte>& msg,
                               u32bit key_bits) const
   {
   return unpad(msg, msg.size(), key_bits);
   }

/*************************************************
* Default signature decoding                     *
*************************************************/
bool EMSA::verify(const MemoryRegion<byte>& coded,
                  const MemoryRegion<byte>& raw,
                  u32bit key_bits) throw()
   {
   try {
      return (coded == encoding_of(raw, key_bits));
      }
   catch(Invalid_Argument)
      {
      return false;
      }
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret.size(),
                     (const byte*)salt.c_str(), salt.length());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const byte salt[], u32bit salt_len) const
   {
   return derive_key(key_len, secret.begin(), secret.size(),
                     salt, salt_len);
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const MemoryRegion<byte>& salt) const
   {
   return derive_key(key_len, secret.begin(), secret.size(),
                     salt.begin(), salt.size());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret_len,
                     (const byte*)salt.c_str(), salt.length());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const byte salt[], u32bit salt_len) const
   {
   return derive(key_len, secret, secret_len, salt, salt_len);
   }

}
