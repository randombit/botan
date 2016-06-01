/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/kdf1.h>

namespace Botan {

size_t KDF1::kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len,
                 const byte label[], size_t label_len) const
   {
   m_hash->update(secret, secret_len);
   m_hash->update(label, label_len);
   m_hash->update(salt, salt_len);

   if(key_len < m_hash->output_length())
      {
      secure_vector<byte> v = m_hash->final();
      copy_mem(key, v.data(), key_len);
      return key_len;
      }

   m_hash->final(key);
   return m_hash->output_length();
   }

}
