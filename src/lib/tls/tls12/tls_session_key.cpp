/*
* TLS Session Key
* (C) 2004-2006,2011,2016,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_session_key.h>

#include <botan/kdf.h>
#include <botan/tls_messages.h>
#include <botan/internal/literals.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan::TLS {

/**
* Session_Keys Constructor
*/
Session_Keys::Session_Keys(const Handshake_State* state,
                           const secure_vector<uint8_t>& pre_master_secret,
                           bool resuming) {
   using namespace literals;

   const size_t cipher_keylen = state->ciphersuite().cipher_keylen();
   const size_t mac_keylen = state->ciphersuite().mac_keylen();
   const size_t cipher_nonce_bytes = state->ciphersuite().nonce_bytes_from_handshake();
   const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_nonce_bytes);

   constexpr auto MASTER_SECRET_MAGIC = "6D617374657220736563726574"_hex;
   constexpr auto EXT_MASTER_SECRET_MAGIC = "657874656E646564206D617374657220736563726574"_hex;
   constexpr auto KEY_GEN_MAGIC = "6B657920657870616E73696F6E"_hex;

   auto prf = state->protocol_specific_prf();

   if(resuming) {
      // This is actually the master secret saved as part of the session
      m_master_sec = pre_master_secret;
   } else {
      const auto [salt, label] = [&]() -> std::pair<secure_vector<uint8_t>, std::span<const uint8_t>> {
         if(state->server_hello()->supports_extended_master_secret()) {
            return {
               state->hash().final(state->ciphersuite().prf_algo()),
               EXT_MASTER_SECRET_MAGIC,
            };
         } else {
            return {
               concat<secure_vector<uint8_t>>(state->client_hello()->random(), state->server_hello()->random()),
               MASTER_SECRET_MAGIC,
            };
         }
      }();

      m_master_sec = prf->derive_key(48, pre_master_secret, salt, label);
   }

   const auto salt = concat(state->server_hello()->random(), state->client_hello()->random());
   const auto prf_output = prf->derive_key(prf_gen, m_master_sec, salt, KEY_GEN_MAGIC);

   m_c_aead.resize(mac_keylen + cipher_keylen);
   m_s_aead.resize(mac_keylen + cipher_keylen);

   BufferSlicer key_material(prf_output);

   const auto c_aead_mac = key_material.take(mac_keylen);
   const auto s_aead_mac = key_material.take(mac_keylen);
   const auto c_aead_cipher = key_material.take(cipher_keylen);
   const auto s_aead_cipher = key_material.take(cipher_keylen);

   m_c_aead = concat<secure_vector<uint8_t>>(c_aead_mac, c_aead_cipher);
   m_s_aead = concat<secure_vector<uint8_t>>(s_aead_mac, s_aead_cipher);
   m_c_nonce = key_material.copy_as_vector(cipher_nonce_bytes);
   m_s_nonce = key_material.copy_as_vector(cipher_nonce_bytes);

   BOTAN_ASSERT_NOMSG(key_material.empty());
}

}  // namespace Botan::TLS
