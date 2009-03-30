/*
* KDF Base Class
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/kdf.h>

namespace Botan {

/*
* Derive a key
*/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret.size(),
                     reinterpret_cast<const byte*>(salt.data()),
                     salt.length());
   }

/*
* Derive a key
*/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const byte salt[], u32bit salt_len) const
   {
   return derive_key(key_len, secret.begin(), secret.size(),
                     salt, salt_len);
   }

/*
* Derive a key
*/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const MemoryRegion<byte>& salt) const
   {
   return derive_key(key_len, secret.begin(), secret.size(),
                     salt.begin(), salt.size());
   }

/*
* Derive a key
*/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret_len,
                     reinterpret_cast<const byte*>(salt.data()),
                     salt.length());
   }

/*
* Derive a key
*/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const byte salt[], u32bit salt_len) const
   {
   return derive(key_len, secret, secret_len, salt, salt_len);
   }

}
