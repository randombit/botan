/*
* TLS Session Key
* (C) 2004-2006,2011,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>

namespace Botan {

namespace TLS {

/**
* Session_Keys Constructor
*/
Session_Keys::Session_Keys(const Handshake_State* state,
                           const secure_vector<byte>& pre_master_secret,
                           bool resuming)
   {
   const size_t cipher_keylen = state->ciphersuite().cipher_keylen();
   const size_t mac_keylen = state->ciphersuite().mac_keylen();
   const size_t cipher_nonce_bytes = state->ciphersuite().nonce_bytes_from_handshake();

   const bool extended_master_secret = state->server_hello()->supports_extended_master_secret();

   const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_nonce_bytes);

   const byte MASTER_SECRET_MAGIC[] = {
      0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

   const byte EXT_MASTER_SECRET_MAGIC[] = {
      0x65, 0x78, 0x74, 0x65, 0x6E, 0x64, 0x65, 0x64, 0x20,
      0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

   const byte KEY_GEN_MAGIC[] = {
      0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E };

   std::unique_ptr<KDF> prf(state->protocol_specific_prf());

   if(resuming)
      {
      // This is actually the master secret saved as part of the session
      m_master_sec = pre_master_secret;
      }
   else
      {
      secure_vector<byte> salt;
      secure_vector<byte> label;
      if(extended_master_secret)
         {
         label += std::make_pair(EXT_MASTER_SECRET_MAGIC, sizeof(EXT_MASTER_SECRET_MAGIC));
         salt += state->hash().final(state->version(),
                                     state->ciphersuite().prf_algo());
         }
      else
         {
         label += std::make_pair(MASTER_SECRET_MAGIC, sizeof(MASTER_SECRET_MAGIC));
         salt += state->client_hello()->random();
         salt += state->server_hello()->random();
         }

      m_master_sec = prf->derive_key(48, pre_master_secret, salt, label);
      }

   secure_vector<byte> salt;
   secure_vector<byte> label;
   label += std::make_pair(KEY_GEN_MAGIC, sizeof(KEY_GEN_MAGIC));
   salt += state->server_hello()->random();
   salt += state->client_hello()->random();

   SymmetricKey keyblock = prf->derive_key(prf_gen, m_master_sec, salt, label);

   const byte* key_data = keyblock.begin();

   m_c_mac = SymmetricKey(key_data, mac_keylen);
   key_data += mac_keylen;

   m_s_mac = SymmetricKey(key_data, mac_keylen);
   key_data += mac_keylen;

   m_c_cipher = SymmetricKey(key_data, cipher_keylen);
   key_data += cipher_keylen;

   m_s_cipher = SymmetricKey(key_data, cipher_keylen);
   key_data += cipher_keylen;

   m_c_iv = InitializationVector(key_data, cipher_nonce_bytes);
   key_data += cipher_nonce_bytes;

   m_s_iv = InitializationVector(key_data, cipher_nonce_bytes);
   }

}

}
