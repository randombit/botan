/*
* TLS Session Key
* (C) 2004-2006,2011,2016,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_session_key.h>

#include <botan/kdf.h>
#include <botan/mem_ops.h>
#include <botan/tls_messages_12.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/tls_handshake_state.h>

namespace Botan::TLS {

/**
* Session_Keys Constructor
*/
Session_Keys::Session_Keys(const Handshake_State* state,
                           const secure_vector<uint8_t>& pre_master_secret,
                           bool resuming) {
   using namespace std::literals;

   BOTAN_ASSERT_NONNULL(state);

   const auto& suite = state->ciphersuite();
   BOTAN_STATE_CHECK(suite.valid());

   const size_t cipher_keylen = suite.cipher_keylen();
   const size_t mac_keylen = suite.mac_keylen();
   const size_t cipher_nonce_bytes = suite.nonce_bytes_from_handshake();

   const bool extended_master_secret = state->server_hello().supports_extended_master_secret();

   const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_nonce_bytes);

   auto prf = state->protocol_specific_prf();

   if(resuming) {
      // This is actually the master secret saved as part of the session
      m_master_sec = pre_master_secret;
   } else {
      const auto label = extended_master_secret  //
                            ? "extended master secret"sv
                            : "master secret"sv;
      const auto salt = extended_master_secret  //
                           ? state->hash().final(suite.prf_algo())
                           : concat(state->client_hello().random(), state->server_hello().random());

      m_master_sec = prf->derive_key(48, pre_master_secret, salt, as_span_of_bytes(label));
   }

   const auto salt = concat(state->server_hello().random(), state->client_hello().random());
   const auto prf_output = prf->derive_key(prf_gen, m_master_sec, salt, as_span_of_bytes("key expansion"sv));

   const uint8_t* key_data = prf_output.data();

   m_c_aead.resize(mac_keylen + cipher_keylen);
   m_s_aead.resize(mac_keylen + cipher_keylen);

   // NOLINTBEGIN(readability-container-data-pointer)
   copy_mem(&m_c_aead[0], key_data, mac_keylen);
   copy_mem(&m_s_aead[0], key_data + mac_keylen, mac_keylen);
   // NOLINTEND(readability-container-data-pointer)

   // Key is not used for NULL suites
   if(cipher_keylen > 0) {
      copy_mem(&m_c_aead[mac_keylen], key_data + 2 * mac_keylen, cipher_keylen);
      copy_mem(&m_s_aead[mac_keylen], key_data + 2 * mac_keylen + cipher_keylen, cipher_keylen);
   } else {
      BOTAN_STATE_CHECK(suite.null_ciphersuite());
   }

   if(cipher_nonce_bytes > 0) {
      const uint8_t* c_nonce_bytes = key_data + 2 * (mac_keylen + cipher_keylen);
      m_c_nonce.assign(c_nonce_bytes, c_nonce_bytes + cipher_nonce_bytes);

      const uint8_t* s_nonce_bytes = key_data + 2 * (mac_keylen + cipher_keylen) + cipher_nonce_bytes;
      m_s_nonce.assign(s_nonce_bytes, s_nonce_bytes + cipher_nonce_bytes);
   }
}

}  // namespace Botan::TLS
