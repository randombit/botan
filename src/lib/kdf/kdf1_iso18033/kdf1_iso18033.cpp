/*
* KDF1 from ISO 18033-2
* (C) 2016 Philipp Weber
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf1_iso18033.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>

namespace Botan {

void KDF1_18033::perform_kdf(std::span<uint8_t> key,
                             std::span<const uint8_t> secret,
                             std::span<const uint8_t> salt,
                             std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const size_t blocks_required = key.size() / m_hash->output_length();
   BOTAN_ARG_CHECK(blocks_required < 0xFFFFFFFF, "KDF1-18033 maximum output length exceeeded");

   secure_vector<uint8_t> h;

   BufferStuffer k(key);
   for(uint32_t counter = 0; !k.full(); ++counter) {
      m_hash->update(secret);
      m_hash->update_be(counter);
      m_hash->update(label);
      m_hash->update(salt);
      m_hash->final(h);

      const auto bytes_to_write = std::min(h.size(), k.remaining_capacity());
      k.append(std::span{h}.first(bytes_to_write));
   }
}

std::string KDF1_18033::name() const {
   return fmt("KDF1-18033({})", m_hash->name());
}

std::unique_ptr<KDF> KDF1_18033::new_object() const {
   return std::make_unique<KDF1_18033>(m_hash->new_object());
}

}  // namespace Botan
