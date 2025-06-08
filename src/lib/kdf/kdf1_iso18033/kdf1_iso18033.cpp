/*
* KDF1 from ISO 18033-2
* (C) 2016 Philipp Weber
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf1_iso18033.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
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

   const auto hash_output_length = m_hash->output_length();
   const auto blocks_required = ceil_division<uint64_t /* for 32bit systems */>(key.size(), hash_output_length);

   // This KDF uses a 32-bit counter for the hash blocks, initialized at 0.
   // It will wrap around after 2^32 iterations which limits the theoretically
   // possible output to 2^32 blocks.
   BOTAN_ARG_CHECK(blocks_required <= 0xFFFFFFFF, "KDF1-18033 maximum output length exceeeded");

   BufferStuffer k(key);
   for(uint32_t counter = 0; !k.full(); ++counter) {
      m_hash->update(secret);
      m_hash->update_be(counter);
      m_hash->update(label);
      m_hash->update(salt);

      // Write straight into the output buffer, except if the hash output needs
      // a truncation in the final iteration.
      if(k.remaining_capacity() >= hash_output_length) {
         m_hash->final(k.next(hash_output_length));
      } else {
         const auto h = m_hash->final();
         k.append(std::span{h}.first(k.remaining_capacity()));
      }
   }
}

std::string KDF1_18033::name() const {
   return fmt("KDF1-18033({})", m_hash->name());
}

std::unique_ptr<KDF> KDF1_18033::new_object() const {
   return std::make_unique<KDF1_18033>(m_hash->new_object());
}

}  // namespace Botan
