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
OctetString PKCS5_PBKDF1::derive_key(u32bit key_len,
                                     const std::string& passphrase,
                                     const byte salt[], u32bit salt_size,
                                     u32bit iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument("PKCS5_PBKDF1: Invalid iteration count");

   if(key_len > hash->OUTPUT_LENGTH)
      throw Invalid_Argument("PKCS5_PBKDF1: Requested output length too long");

   hash->update(passphrase);
   hash->update(salt, salt_size);
   SecureVector<byte> key = hash->final();

   for(u32bit j = 1; j != iterations; ++j)
      {
      hash->update(key);
      hash->final(key);
      }

   return OctetString(key, std::min<u32bit>(key_len, key.size()));
   }

}
