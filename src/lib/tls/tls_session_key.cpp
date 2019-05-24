/*
* TLS Session Key
* (C) 2004-2006,2011,2016,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/tls_messages.h>
#include <botan/kdf.h>

namespace Botan {

namespace TLS {

/**
* Session_Keys Constructor
*/
Session_Keys::Session_Keys(const Handshake_State* state,
                           const secure_vector<uint8_t>& pre_master_secret,
                           bool resuming)
   {
   const size_t cipher_keylen = state->ciphersuite().cipher_keylen();
   const size_t mac_keylen = state->ciphersuite().mac_keylen();
   const size_t cipher_nonce_bytes = state->ciphersuite().nonce_bytes_from_handshake();

   const bool extended_master_secret = state->server_hello()->supports_extended_master_secret();

   const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_nonce_bytes);

   const uint8_t MASTER_SECRET_MAGIC[] = {
      0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

   const uint8_t EXT_MASTER_SECRET_MAGIC[] = {
      0x65, 0x78, 0x74, 0x65, 0x6E, 0x64, 0x65, 0x64, 0x20,
      0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

   const uint8_t KEY_GEN_MAGIC[] = {
      0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E };

   std::unique_ptr<KDF> prf(state->protocol_specific_prf());

   if(resuming)
      {
      // This is actually the master secret saved as part of the session
      m_master_sec = pre_master_secret;
      }
   else
      {
      std::vector<uint8_t> salt;
      std::vector<uint8_t> label;
      if(extended_master_secret)
         {
         label.assign(EXT_MASTER_SECRET_MAGIC, EXT_MASTER_SECRET_MAGIC + sizeof(EXT_MASTER_SECRET_MAGIC));
         salt += state->hash().final(state->version(),
                                     state->ciphersuite().prf_algo());
         }
      else
         {
         label.assign(MASTER_SECRET_MAGIC, MASTER_SECRET_MAGIC + sizeof(MASTER_SECRET_MAGIC));
         salt += state->client_hello()->random();
         salt += state->server_hello()->random();
         }

      m_master_sec = prf->derive_key(48, pre_master_secret, salt, label);
      }

   std::vector<uint8_t> salt;
   std::vector<uint8_t> label;
   label.assign(KEY_GEN_MAGIC, KEY_GEN_MAGIC + sizeof(KEY_GEN_MAGIC));
   salt += state->server_hello()->random();
   salt += state->client_hello()->random();

   const secure_vector<uint8_t> prf_output = prf->derive_key(
      prf_gen,
      m_master_sec.data(), m_master_sec.size(),
      salt.data(), salt.size(),
      label.data(), label.size());

   const uint8_t* key_data = prf_output.data();

   m_c_aead.resize(mac_keylen + cipher_keylen);
   m_s_aead.resize(mac_keylen + cipher_keylen);

   copy_mem(&m_c_aead[0], key_data, mac_keylen);
   copy_mem(&m_s_aead[0], key_data + mac_keylen, mac_keylen);

   copy_mem(&m_c_aead[mac_keylen], key_data + 2*mac_keylen, cipher_keylen);
   copy_mem(&m_s_aead[mac_keylen], key_data + 2*mac_keylen + cipher_keylen, cipher_keylen);

   m_c_nonce.resize(cipher_nonce_bytes);
   m_s_nonce.resize(cipher_nonce_bytes);

   copy_mem(&m_c_nonce[0], key_data + 2*(mac_keylen + cipher_keylen), cipher_nonce_bytes);
   copy_mem(&m_s_nonce[0], key_data + 2*(mac_keylen + cipher_keylen) + cipher_nonce_bytes, cipher_nonce_bytes);
   }

}

}
