/*
* KMAC
* (C) 2023 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kmac.h>

#include <botan/internal/cshake_xof.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keccak_helpers.h>

namespace Botan {

void KMAC256::clear() {
   zap(m_key);
   m_message_started = false;
   m_cshake.clear();
}

std::string KMAC256::name() const {
   return fmt("KMAC-256({})", m_output_bit_length);
}

std::unique_ptr<MessageAuthenticationCode> KMAC256::new_object() const {
   return std::make_unique<KMAC256>(m_output_bit_length);
}

size_t KMAC256::output_length() const {
   return m_output_bit_length / 8;
}

Key_Length_Specification KMAC256::key_spec() const {
   // KMAC supports key lengths from zero up to 2²⁰⁴⁰ (2^(2040)) bits:
   // https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf#page=28
   //
   // However, we restrict the key length to 64 bytes in order to avoid allocation of overly
   // large memory stretches when client code works with the maximal key length.
   return Key_Length_Specification(0, 64);
}

bool KMAC256::has_keying_material() const {
   return !m_key.empty();
}

void KMAC256::start_msg(const uint8_t nonce[], size_t nonce_len) {
   assert_key_material_set(!m_key.empty());
   m_cshake.start({nonce, nonce_len}, {});
   keccak_absorb_padded_strings_encoding(m_cshake, m_cshake.block_size(), m_key);
   m_message_started = true;
}

KMAC256::KMAC256(size_t output_bit_length) :
      m_output_bit_length(output_bit_length), m_message_started(false), m_cshake("KMAC") {
   BOTAN_ARG_CHECK(m_output_bit_length % 8 == 0, "KMAC output length must be full bytes");
}

void KMAC256::add_data(std::span<const uint8_t> data) {
   assert_key_material_set(!m_key.empty());
   if(!m_message_started) {
      start();
   }
   m_cshake.update(data);
}

void KMAC256::final_result(std::span<uint8_t> output) {
   assert_key_material_set(!m_key.empty());
   std::array<uint8_t, keccak_max_int_encoding_size()> encoded_output_length_buffer;
   m_cshake.update(keccak_int_right_encode(encoded_output_length_buffer, m_output_bit_length));
   m_cshake.output(output.first(output_length()));
   m_cshake.clear();
   m_message_started = false;
}

void KMAC256::key_schedule(std::span<const uint8_t> key) {
   clear();
   m_key.insert(m_key.end(), key.begin(), key.end());
}

}  // namespace Botan
