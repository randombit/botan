/*
* ChaCha_RNG
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/chacha_rng.h>

#include <botan/assert.h>

namespace Botan {

ChaCha_RNG::ChaCha_RNG(KeyErasure key_erasure) :
      m_hmac(MessageAuthenticationCode::create_or_throw(hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(stream_cipher_algo)),
      m_key_erasure(key_erasure) {
   clear();
}

ChaCha_RNG::ChaCha_RNG(std::span<const uint8_t> seed, KeyErasure key_erasure) : ChaCha_RNG(key_erasure) {
   add_entropy(seed);
}

ChaCha_RNG::ChaCha_RNG(RandomNumberGenerator& underlying_rng, size_t reseed_interval, KeyErasure key_erasure) :
      Stateful_RNG(underlying_rng, reseed_interval),
      m_hmac(MessageAuthenticationCode::create_or_throw(hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(stream_cipher_algo)),
      m_key_erasure(key_erasure) {
   clear();
}

ChaCha_RNG::ChaCha_RNG(RandomNumberGenerator& underlying_rng,
                       Entropy_Sources& entropy_sources,
                       size_t reseed_interval,
                       KeyErasure key_erasure) :
      Stateful_RNG(underlying_rng, entropy_sources, reseed_interval),
      m_hmac(MessageAuthenticationCode::create_or_throw(hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(stream_cipher_algo)),
      m_key_erasure(key_erasure) {
   clear();
}

ChaCha_RNG::ChaCha_RNG(Entropy_Sources& entropy_sources, size_t reseed_interval, KeyErasure key_erasure) :
      Stateful_RNG(entropy_sources, reseed_interval),
      m_hmac(MessageAuthenticationCode::create_or_throw(hmac_algo)),
      m_chacha(StreamCipher::create_or_throw(stream_cipher_algo)),
      m_key_erasure(key_erasure) {
   clear();
}

void ChaCha_RNG::clear_state() {
   m_hmac->set_key(std::vector<uint8_t>(m_hmac->output_length(), 0x00));
   update_chacha_state(m_hmac->final());
}

void ChaCha_RNG::update_chacha_state(std::span<const uint8_t> key_material) {
   /*
   * HMAC(X) should produce more than 32 + 8 = 40 byte. As there is no
   * SHA-320, this check needs to be >= for SHA-384 and SHA-512 or their SHA-3
   * equivalents. SHA-256 won't produce enough output with a single invocation.
   *
   * This assertion is necessary, as key_material has a dynamic extent.
   * km has a fixed extent, which can be checked at compile time.
   */
   BOTAN_ASSERT_NOMSG(key_material.size() >= chacha_key_len + chacha_iv_len);

   const std::span<const uint8_t, chacha_key_len + chacha_iv_len> km =
      key_material.first<chacha_key_len + chacha_iv_len>();
   m_chacha->set_key(km.first<chacha_key_len>());
   m_chacha->set_iv(km.last<chacha_iv_len>());
}

void ChaCha_RNG::generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) {
   BOTAN_ASSERT_NOMSG(!output.empty());

   if(!input.empty()) {
      update(input);
   }

   const bool erase_key = (m_key_erasure == KeyErasure::WithKeyErasure);

   // Use a fixed structure for fast key erasure. Next key is always the first output of
   // the keystream (without updates in between). Therefore the next key becomes independent
   // of the request pattern. This should not harm security and may ease mathematical analysis,
   // as no variable position of the next key in the output stream has to be modeled.
   std::array<uint8_t, chacha_key_len + chacha_iv_len> key_material{};
   if(erase_key) {
      m_chacha->write_keystream(key_material);
   }

   m_chacha->write_keystream(output);

   // optionally overwrite key after each output operation for backtracking resistance
   if(erase_key) {
      update_chacha_state(key_material);
   }
}

void ChaCha_RNG::update(std::span<const uint8_t> input) {
   update_chacha_state(m_hmac->process(input));
   m_hmac->set_key(m_chacha->keystream_bytes(m_hmac->output_length()));
}

size_t ChaCha_RNG::security_level() const {
   /*
    * as we use a 64 bit nonce as extended key and a wide enough hash
    * function with SHA-512, could also be set to 256 + 64 = 320
    */
   return 256;
}

}  // namespace Botan
