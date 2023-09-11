/**
 * Wrapper for truncated hashes
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/trunc_hash.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

void Truncated_Hash::add_data(std::span<const uint8_t> input) {
   m_hash->update(input);
}

void Truncated_Hash::final_result(std::span<uint8_t> out) {
   BOTAN_ASSERT_NOMSG(m_hash->output_length() * 8 >= m_output_bits);

   m_hash->final(m_buffer);

   // truncate output to a full number of bytes
   const auto bytes = output_length();
   std::copy_n(m_buffer.begin(), bytes, out.data());
   zeroise(m_buffer);

   // mask the unwanted bits in the final byte
   const uint8_t bits_in_last_byte = ((m_output_bits - 1) % 8) + 1;
   const uint8_t bitmask = ~((1 << (8 - bits_in_last_byte)) - 1);

   out.back() &= bitmask;
}

size_t Truncated_Hash::output_length() const {
   return (m_output_bits + 7) / 8;
}

std::string Truncated_Hash::name() const {
   return fmt("Truncated({},{})", m_hash->name(), m_output_bits);
}

std::unique_ptr<HashFunction> Truncated_Hash::new_object() const {
   return std::make_unique<Truncated_Hash>(m_hash->new_object(), m_output_bits);
}

std::unique_ptr<HashFunction> Truncated_Hash::copy_state() const {
   return std::make_unique<Truncated_Hash>(m_hash->copy_state(), m_output_bits);
}

void Truncated_Hash::clear() {
   m_hash->clear();
}

Truncated_Hash::Truncated_Hash(std::unique_ptr<HashFunction> hash, size_t bits) :
      m_hash(std::move(hash)), m_output_bits(bits), m_buffer(m_hash->output_length()) {
   BOTAN_ASSERT_NONNULL(m_hash);

   if(m_output_bits == 0) {
      throw Invalid_Argument("Truncating a hash to 0 does not make sense");
   }

   if(m_hash->output_length() * 8 < m_output_bits) {
      throw Invalid_Argument("Underlying hash function does not produce enough bytes for truncation");
   }
}

}  // namespace Botan
