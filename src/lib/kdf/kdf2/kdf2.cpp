/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf2.h>

namespace Botan {

size_t KDF2::kdf(uint8_t key[], size_t key_len,
                 const uint8_t secret[], size_t secret_len,
                 const uint8_t salt[], size_t salt_len,
                 const uint8_t label[], size_t label_len) const
   {
   uint32_t counter = 1;
   secure_vector<uint8_t> h;

   size_t offset = 0;
   while(offset != key_len && counter != 0)
      {
      m_hash->update(secret, secret_len);
      m_hash->update_be(counter++);
      m_hash->update(label, label_len);
      m_hash->update(salt, salt_len);
      m_hash->final(h);

      const size_t added = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), added);
      offset += added;
      }

   // FIXME: returns truncated output
   return offset;
   }

}
