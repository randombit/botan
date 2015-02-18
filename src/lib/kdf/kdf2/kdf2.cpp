/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf_utils.h>
#include <botan/kdf2.h>

namespace Botan {

BOTAN_REGISTER_KDF_1HASH(KDF2, "KDF2");

size_t KDF2::kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len) const
   {
   u32bit counter = 1;
   secure_vector<byte> h;

   size_t offset = 0;
   while(offset != key_len && counter != 0)
      {
      m_hash->update(secret, secret_len);
      m_hash->update_be(counter++);
      m_hash->update(salt, salt_len);
      m_hash->final(h);

      const size_t added = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], &h[0], added);
      offset += added;
      }

   return offset;
   }

}
