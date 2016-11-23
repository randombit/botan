/*
* HKDF
* (C) 2013,2015 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hkdf.h>

namespace Botan {

size_t HKDF::kdf(byte key[], size_t key_len,
                 const byte secret[], size_t secret_len,
                 const byte salt[], size_t salt_len,
                 const byte label[], size_t label_len) const
   {
   HKDF_Extract extract(m_prf->clone());
   HKDF_Expand expand(m_prf->clone());
   secure_vector<byte> prk(m_prf->output_length());

   extract.kdf(prk.data(), prk.size(), secret, secret_len, salt, salt_len, nullptr, 0);
   return expand.kdf(key, key_len, prk.data(), prk.size(), nullptr, 0, label, label_len);
   }

size_t HKDF_Extract::kdf(byte key[], size_t key_len,
                         const byte secret[], size_t secret_len,
                         const byte salt[], size_t salt_len,
                         const byte[], size_t) const
   {
   secure_vector<byte> prk;
   if(salt_len == 0)
      {
      m_prf->set_key(std::vector<byte>(m_prf->output_length()));
      }
   else
      {
      m_prf->set_key(salt, salt_len);
      }

   m_prf->update(secret, secret_len);
   m_prf->final(prk);

   const size_t written = std::min(prk.size(), key_len);
   copy_mem(&key[0], prk.data(), written);
   return written;
   }

size_t HKDF_Expand::kdf(byte key[], size_t key_len,
                        const byte secret[], size_t secret_len,
                        const byte salt[], size_t salt_len,
                        const byte label[], size_t label_len) const
   {
   m_prf->set_key(secret, secret_len);

   byte counter = 1;
   secure_vector<byte> h;
   size_t offset = 0;

   while(offset != key_len && counter != 0)
      {
      m_prf->update(h);
      m_prf->update(label, label_len);
      m_prf->update(salt, salt_len);
      m_prf->update(counter++);
      m_prf->final(h);

      const size_t written = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), written);
      offset += written;
      }

   return offset;
   }

}
