/*
* ChaCha_RNG
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha_rng.h>

namespace Botan {

ChaCha_RNG::ChaCha_RNG() : Stateful_RNG() {
   m_hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   m_chacha = StreamCipher::create_or_throw("ChaCha(20)");
   clear();
}

ChaCha_RNG::ChaCha_RNG(std::span<const uint8_t> seed) : Stateful_RNG() {
   m_hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   m_chacha = StreamCipher::create_or_throw("ChaCha(20)");
   clear();
   add_entropy(seed);
}

ChaCha_RNG::ChaCha_RNG(RandomNumberGenerator& underlying_rng, size_t reseed_interval) :
      Stateful_RNG(underlying_rng, reseed_interval) {
   m_hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   m_chacha = StreamCipher::create_or_throw("ChaCha(20)");
   clear();
}

ChaCha_RNG::ChaCha_RNG(RandomNumberGenerator& underlying_rng,
                       Entropy_Sources& entropy_sources,
                       size_t reseed_interval) :
      Stateful_RNG(underlying_rng, entropy_sources, reseed_interval) {
   m_hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   m_chacha = StreamCipher::create_or_throw("ChaCha(20)");
   clear();
}

ChaCha_RNG::ChaCha_RNG(Entropy_Sources& entropy_sources, size_t reseed_interval) :
      Stateful_RNG(entropy_sources, reseed_interval) {
   m_hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   m_chacha = StreamCipher::create_or_throw("ChaCha(20)");
   clear();
}

void ChaCha_RNG::clear_state() {
   m_hmac->set_key(std::vector<uint8_t>(m_hmac->output_length(), 0x00));
   m_chacha->set_key(m_hmac->final());
}

void ChaCha_RNG::generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) {
   BOTAN_ASSERT_NOMSG(!output.empty());

   if(!input.empty()) {
      update(input);
   }

   m_chacha->write_keystream(output);
}

void ChaCha_RNG::update(std::span<const uint8_t> input) {
   m_hmac->update(input);
   m_chacha->set_key(m_hmac->final());
   const auto mac_key = m_chacha->keystream_bytes(m_hmac->output_length());
   m_hmac->set_key(mac_key);
}

size_t ChaCha_RNG::security_level() const {
   return 256;
}

}  // namespace Botan
