/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf1.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

std::string KDF1::name() const {
   return fmt("KDF1({})", m_hash->name());
}

std::unique_ptr<KDF> KDF1::new_object() const {
   return std::make_unique<KDF1>(m_hash->new_object());
}

void KDF1::kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const {
   if(key_len == 0) {
      return;
   }

   if(key_len > m_hash->output_length()) {
      throw Invalid_Argument("KDF1 maximum output length exceeeded");
   }

   m_hash->update(secret, secret_len);
   m_hash->update(label, label_len);
   m_hash->update(salt, salt_len);

   if(key_len == m_hash->output_length()) {
      // In this case we can hash directly into the output buffer
      m_hash->final(key);
   } else {
      // Otherwise a copy is required
      secure_vector<uint8_t> v = m_hash->final();
      copy_mem(key, v.data(), key_len);
   }
}

}  // namespace Botan
