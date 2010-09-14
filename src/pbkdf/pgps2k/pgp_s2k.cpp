/*
* OpenPGP S2K
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pgp_s2k.h>

namespace Botan {

/*
* Derive a key using the OpenPGP S2K algorithm
*/
OctetString OpenPGP_S2K::derive_key(u32bit key_len,
                                    const std::string& passphrase,
                                    const byte salt_buf[], u32bit salt_size,
                                    u32bit iterations) const
   {
   SecureVector<byte> key(key_len), hash_buf;

   u32bit pass = 0, generated = 0,
          total_size = passphrase.size() + salt_size;
   u32bit to_hash = std::max(iterations, total_size);

   hash->clear();
   while(key_len > generated)
      {
      for(u32bit j = 0; j != pass; ++j)
         hash->update(0);

      u32bit left = to_hash;
      while(left >= total_size)
         {
         hash->update(salt_buf, salt_size);
         hash->update(passphrase);
         left -= total_size;
         }
      if(left <= salt_size)
         hash->update(salt_buf, left);
      else
         {
         hash->update(salt_buf, salt_size);
         left -= salt_size;
         hash->update(reinterpret_cast<const byte*>(passphrase.data()), left);
         }

      hash_buf = hash->final();
      key.copy(generated, &hash_buf[0], hash->OUTPUT_LENGTH);
      generated += hash->OUTPUT_LENGTH;
      ++pass;
      }

   return key;
   }

}
