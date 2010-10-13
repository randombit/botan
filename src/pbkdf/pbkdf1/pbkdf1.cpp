/*
* PBKDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbkdf1.h>
#include <botan/exceptn.h>

namespace Botan {

/*
* Return a PKCS#5 PBKDF1 derived key
*/
OctetString PKCS5_PBKDF1::derive_key(size_t key_len,
                                     const std::string& passphrase,
                                     const byte salt[], size_t salt_size,
                                     size_t iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument("PKCS5_PBKDF1: Invalid iteration count");

   if(key_len > hash->output_length())
      throw Invalid_Argument("PKCS5_PBKDF1: Requested output length too long");

   hash->update(passphrase);
   hash->update(salt, salt_size);
   SecureVector<byte> key = hash->final();

   for(size_t j = 1; j != iterations; ++j)
      {
      hash->update(key);
      hash->final(&key[0]);
      }

   return OctetString(&key[0], std::min<size_t>(key_len, key.size()));
   }

}
