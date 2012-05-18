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
secure_vector<byte> KDF::derive_key(size_t key_len,
                                   const secure_vector<byte>& secret,
                                   const std::string& salt) const
   {
   return derive_key(key_len, &secret[0], secret.size(),
                     reinterpret_cast<const byte*>(salt.data()),
                     salt.length());
   }

/*
* Derive a key
*/
secure_vector<byte> KDF::derive_key(size_t key_len,
                                   const secure_vector<byte>& secret,
                                   const byte salt[], size_t salt_len) const
   {
   return derive_key(key_len, &secret[0], secret.size(),
                     salt, salt_len);
   }

/*
* Derive a key
*/
secure_vector<byte> KDF::derive_key(size_t key_len,
                                   const byte secret[], size_t secret_len,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret_len,
                     reinterpret_cast<const byte*>(salt.data()),
                     salt.length());
   }

/*
* Derive a key
*/
secure_vector<byte> KDF::derive_key(size_t key_len,
                                   const byte secret[], size_t secret_len,
                                   const byte salt[], size_t salt_len) const
   {
   return derive(key_len, secret, secret_len, salt, salt_len);
   }

}
