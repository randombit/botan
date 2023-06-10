/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf2.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

std::string KDF2::name() const {
   return fmt("KDF2({})", m_hash->name());
}

std::unique_ptr<KDF> KDF2::new_object() const {
   return std::make_unique<KDF2>(m_hash->new_object());
}

void KDF2::kdf(uint8_t key[],
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

   const size_t blocks_required = key_len / m_hash->output_length();

   if(blocks_required >= 0xFFFFFFFE) {
      throw Invalid_Argument("KDF2 maximum output length exceeeded");
   }

   uint32_t counter = 1;
   secure_vector<uint8_t> h;

   size_t offset = 0;
   while(offset != key_len) {
      m_hash->update(secret, secret_len);
      m_hash->update_be(counter);
      m_hash->update(label, label_len);
      m_hash->update(salt, salt_len);
      m_hash->final(h);

      const size_t added = std::min(h.size(), key_len - offset);
      copy_mem(&key[offset], h.data(), added);
      offset += added;

      counter += 1;
      BOTAN_ASSERT_NOMSG(counter != 0);  // no overflow
   }
}

}  // namespace Botan
