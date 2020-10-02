/*
* KDF defined in NIST SP 800-56c
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sp800_56c.h>

namespace Botan {

size_t SP800_56C::kdf(uint8_t key[], size_t key_len,
                      const uint8_t secret[], size_t secret_len,
                      const uint8_t salt[], size_t salt_len,
                      const uint8_t label[], size_t label_len) const
   {
   // Randomness Extraction
   secure_vector<uint8_t> k_dk;

   m_prf->set_key(salt, salt_len);
   m_prf->update(secret, secret_len);
   m_prf->final(k_dk);

   // Key Expansion
   return m_exp->kdf(key, key_len, k_dk.data(), k_dk.size(), nullptr, 0, label, label_len);
   }

}
