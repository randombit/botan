/*
* KDF1
* (C) 1999-2007 Jack Lloyd
* (C) 2024      René Meusel, Rohde & Schwarz Cybersecurity
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

void KDF1::perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const size_t hash_output_len = m_hash->output_length();
   BOTAN_ARG_CHECK(key.size() <= hash_output_len, "KDF1 maximum output length exceeeded");

   m_hash->update(secret);
   m_hash->update(label);
   m_hash->update(salt);

   if(key.size() == hash_output_len) {
      // In this case we can hash directly into the output buffer
      m_hash->final(key);
   } else {
      // Otherwise a copy is required
      const auto v = m_hash->final();
      copy_mem(key, std::span{v}.first(key.size()));
   }
}

}  // namespace Botan
