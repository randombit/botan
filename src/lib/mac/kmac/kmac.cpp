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

KMAC::KMAC(std::unique_ptr<cSHAKE_XOF> cshake, size_t output_bit_length) :
      m_output_bit_length(output_bit_length), m_message_started(false), m_cshake(std::move(cshake)) {
   BOTAN_ARG_CHECK(m_output_bit_length % 8 == 0, "KMAC output length must be full bytes");
   BOTAN_ARG_CHECK(m_output_bit_length > 0, "KMAC output length must be at least one byte");
   BOTAN_ASSERT_NONNULL(m_cshake);
}

KMAC::~KMAC() = default;

void KMAC::clear() {
   zap(m_encoded_key);
   m_message_started = false;
   m_cshake->clear();
}

size_t KMAC::output_length() const {
   return m_output_bit_length / 8;
}

Key_Length_Specification KMAC::key_spec() const {
   // KMAC supports key lengths from zero up to 2²⁰⁴⁰ (2^(2040)) bits:
   // https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf#page=28
   //
   // However, we restrict the key length to 192 bytes in order to avoid allocation of overly
   // large memory stretches when client code works with the maximal key length. We chose a
   // boundary that contains the length of the default_salt of the one-step KDM with KMAC128
   // of 164 bytes. (see NIST SP 800-56C Rev. 2, Section 4.1, Implementation-Dependent Parameters 3.).
   return Key_Length_Specification(0, 192);
}

bool KMAC::has_keying_material() const {
   return !m_encoded_key.empty();
}

std::string KMAC::provider() const {
   return m_cshake->provider();
}

void KMAC::start_msg(std::span<const uint8_t> nonce) {
   assert_key_material_set();
   m_cshake->start(nonce);
   m_cshake->update(m_encoded_key);
   m_message_started = true;
}

void KMAC::add_data(std::span<const uint8_t> data) {
   assert_key_material_set(!m_encoded_key.empty());
   if(!m_message_started) {
      start();
   }
   m_cshake->update(data);
}

void KMAC::final_result(std::span<uint8_t> output) {
   assert_key_material_set();
   std::array<uint8_t, keccak_max_int_encoding_size()> encoded_output_length_buffer;
   m_cshake->update(keccak_int_right_encode(encoded_output_length_buffer, m_output_bit_length));
   m_cshake->output(output.first(output_length()));
   m_cshake->clear();
   m_message_started = false;
}

void KMAC::key_schedule(std::span<const uint8_t> key) {
   clear();
   keccak_absorb_padded_strings_encoding(m_encoded_key, m_cshake->block_size(), key);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

KMAC128::KMAC128(size_t output_bit_length) : KMAC(std::make_unique<cSHAKE_128_XOF>("KMAC"), output_bit_length) {}

std::string KMAC128::name() const {
   return fmt("KMAC-128({})", output_length() * 8);
}

std::unique_ptr<MessageAuthenticationCode> KMAC128::new_object() const {
   return std::make_unique<KMAC128>(output_length() * 8);
}

KMAC256::KMAC256(size_t output_bit_length) : KMAC(std::make_unique<cSHAKE_256_XOF>("KMAC"), output_bit_length) {}

std::string KMAC256::name() const {
   return fmt("KMAC-256({})", output_length() * 8);
}

std::unique_ptr<MessageAuthenticationCode> KMAC256::new_object() const {
   return std::make_unique<KMAC256>(output_length() * 8);
}

}  // namespace Botan
