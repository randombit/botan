/*
* KDF2
* (C) 1999-2007 Jack Lloyd
* (C) 2024      René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf2.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::string KDF2::name() const {
   return fmt("KDF2({})", m_hash->name());
}

std::unique_ptr<KDF> KDF2::new_object() const {
   return std::make_unique<KDF2>(m_hash->new_object());
}

void KDF2::perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const size_t hash_output_length = m_hash->output_length();
   const auto blocks_required = ceil_division<uint64_t /* for 32bit systems */>(key.size(), hash_output_length);

   // This KDF uses a 32-bit counter for the hash blocks, initialized at 1.
   // It will wrap around after 2^32 - 1 iterations limiting the theoretically
   // possible output to 2^32 - 1 blocks.
   BOTAN_ARG_CHECK(blocks_required <= 0xFFFFFFFE, "KDF2 maximum output length exceeeded");

   BufferStuffer k(key);
   for(uint32_t counter = 1; !k.full(); ++counter) {
      BOTAN_ASSERT_NOMSG(counter != 0);  // no overflow

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

}  // namespace Botan
