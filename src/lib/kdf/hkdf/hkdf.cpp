/*
* HKDF
* (C) 2013,2015 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hkdf.h>

namespace Botan {

size_t HKDF::kdf(uint8_t key[], size_t key_len,
                 const uint8_t secret[], size_t secret_len,
                 const uint8_t salt[], size_t salt_len,
                 const uint8_t label[], size_t label_len) const
   {
   HKDF_Extract extract(m_prf->clone());
   HKDF_Expand expand(m_prf->clone());
   secure_vector<uint8_t> prk(m_prf->output_length());

   extract.kdf(prk.data(), prk.size(), secret, secret_len, salt, salt_len, nullptr, 0);
   return expand.kdf(key, key_len, prk.data(), prk.size(), nullptr, 0, label, label_len);
   }

size_t HKDF_Extract::kdf(uint8_t key[], size_t key_len,
                         const uint8_t secret[], size_t secret_len,
                         const uint8_t salt[], size_t salt_len,
                         const uint8_t[], size_t) const
   {
   secure_vector<uint8_t> prk;
   if(salt_len == 0)
      {
      m_prf->set_key(std::vector<uint8_t>(m_prf->output_length()));
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

size_t HKDF_Expand::kdf(uint8_t key[], size_t key_len,
                        const uint8_t secret[], size_t secret_len,
                        const uint8_t salt[], size_t salt_len,
                        const uint8_t label[], size_t label_len) const
   {
   m_prf->set_key(secret, secret_len);

   uint8_t counter = 1;
   secure_vector<uint8_t> h;
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
