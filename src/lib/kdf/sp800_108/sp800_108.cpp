/*
* KDFs defined in NIST SP 800-108
* (C) 2016 Kai Michaelis
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp800_108.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::string SP800_108_Counter::name() const {
   return fmt("SP800-108-Counter({})", m_prf->name());
}

std::unique_ptr<KDF> SP800_108_Counter::new_object() const {
   return std::make_unique<SP800_108_Counter>(m_prf->new_object());
}

void SP800_108_Counter::perform_kdf(std::span<uint8_t> key,
                                    std::span<const uint8_t> secret,
                                    std::span<const uint8_t> salt,
                                    std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const auto length = static_cast<uint32_t>(key.size() * 8);
   const auto prf_len = m_prf->output_length();
   const auto blocks_required = ceil_division<uint64_t /* for 32bit systems */>(key.size(), prf_len);

   // This KDF uses a 32-bit counter for the hash blocks, initialized at 1.
   // It will wrap around after 2^32 - 1 iterations limiting the theoretically
   // possible output to 2^32 - 1 blocks.
   BOTAN_ARG_CHECK(blocks_required <= 0xFFFFFFFE, "SP800_108_Counter output size too large");

   constexpr uint8_t delim = 0;

   BufferStuffer k(key);
   m_prf->set_key(secret);
   for(uint32_t counter = 1; !k.full(); ++counter) {
      BOTAN_ASSERT(counter != 0, "No counter overflow");

      m_prf->update(store_be(counter));
      m_prf->update(label);
      m_prf->update(delim);
      m_prf->update(salt);
      m_prf->update(store_be(length));

      // Write straight into the output buffer, except if the PRF output needs
      // a truncation in the final iteration.
      if(k.remaining_capacity() >= prf_len) {
         m_prf->final(k.next(prf_len));
      } else {
         const auto h = m_prf->final();
         k.append(std::span{h}.first(k.remaining_capacity()));
      }
   }
}

std::string SP800_108_Feedback::name() const {
   return fmt("SP800-108-Feedback({})", m_prf->name());
}

std::unique_ptr<KDF> SP800_108_Feedback::new_object() const {
   return std::make_unique<SP800_108_Feedback>(m_prf->new_object());
}

void SP800_108_Feedback::perform_kdf(std::span<uint8_t> key,
                                     std::span<const uint8_t> secret,
                                     std::span<const uint8_t> salt,
                                     std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const auto length = static_cast<uint32_t>(key.size() * 8);
   const auto prf_len = m_prf->output_length();
   const auto iv_len = (salt.size() >= prf_len ? prf_len : 0);
   constexpr uint8_t delim = 0;

   const uint64_t blocks_required = (key.size() + prf_len - 1) / prf_len;
   BOTAN_ARG_CHECK(blocks_required < 0xFFFFFFFF, "SP800_108_Feedback output size too large");

   BufferSlicer s(salt);
   auto prev = s.copy_as_secure_vector(iv_len);
   const auto ctx = s.take(s.remaining());
   BOTAN_ASSERT_NOMSG(s.empty());

   BufferStuffer k(key);
   m_prf->set_key(secret);
   for(uint32_t counter = 1; !k.full(); ++counter) {
      BOTAN_ASSERT(counter != 0, "No counter overflow");

      m_prf->update(prev);
      m_prf->update(store_be(counter));
      m_prf->update(label);
      m_prf->update(delim);
      m_prf->update(ctx);
      m_prf->update(store_be(length));
      m_prf->final(prev);

      const auto bytes_to_write = std::min(prev.size(), k.remaining_capacity());
      k.append(std::span{prev}.first(bytes_to_write));
   }
}

std::string SP800_108_Pipeline::name() const {
   return fmt("SP800-108-Pipeline({})", m_prf->name());
}

std::unique_ptr<KDF> SP800_108_Pipeline::new_object() const {
   return std::make_unique<SP800_108_Pipeline>(m_prf->new_object());
}

void SP800_108_Pipeline::perform_kdf(std::span<uint8_t> key,
                                     std::span<const uint8_t> secret,
                                     std::span<const uint8_t> salt,
                                     std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const auto length = static_cast<uint32_t>(key.size() * 8);
   const auto prf_len = m_prf->output_length();
   constexpr uint8_t delim = 0;

   const uint64_t blocks_required = (key.size() + prf_len - 1) / prf_len;
   BOTAN_ARG_CHECK(blocks_required < 0xFFFFFFFF, "SP800_108_Feedback output size too large");

   // A(0)
   auto ai = concat<secure_vector<uint8_t>>(label, store_be(delim), salt, store_be(length));
   secure_vector<uint8_t> ki;

   BufferStuffer k(key);
   m_prf->set_key(secret);
   for(uint32_t counter = 1; !k.full(); ++counter) {
      BOTAN_ASSERT(counter != 0, "No counter overflow");

      // A(i)
      m_prf->update(ai);
      m_prf->final(ai);

      // K(i)
      m_prf->update(ai);
      m_prf->update(store_be(counter));
      m_prf->update(label);
      m_prf->update(delim);
      m_prf->update(salt);
      m_prf->update(store_be(length));
      m_prf->final(ki);

      const auto bytes_to_write = std::min(ki.size(), k.remaining_capacity());
      k.append(std::span{ki}.first(bytes_to_write));
   }
}

}  // namespace Botan
