/*
* TLS Client - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/**
 * Cipher_State state machine adapted from RFC 8446 7.1.
 *
 *                                     0
 *                                     |
 *                                     v
 *                           PSK ->  HKDF-Extract = Early Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "ext binder" | "res binder", "")
 *                                     |                     = binder_key
 *                                     |
 *                                     +-----> Derive-Secret(., "c e traffic", ClientHello)
 *                                     |                     = client_early_traffic_secret
 *                                     |
 *                                     +-----> Derive-Secret(., "e exp master", ClientHello)
 *                                     |                     = early_exporter_master_secret
 *                                     v
 *                               Derive-Secret(., "derived", "")
 *                                     |
 *                                     *
 *                             STATE EARLY TRAFFIC
 * This state is reached by constructing Cipher_State using init_with_psk() (not yet implemented).
 * The state can then be further advanced using advance_with_server_hello().
 *                                     *
 *                                     |
 *                                     v
 *                           (EC)DHE -> HKDF-Extract = Handshake Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "c hs traffic",
 *                                     |                     ClientHello...ServerHello)
 *                                     |                     = client_handshake_traffic_secret
 *                                     |
 *                                     +-----> Derive-Secret(., "s hs traffic",
 *                                     |                     ClientHello...ServerHello)
 *                                     |                     = server_handshake_traffic_secret
 *                                     v
 *                               Derive-Secret(., "derived", "")
 *                                     |
 *                                     *
 *                          STATE HANDSHAKE TRAFFIC
 * This state is reached by constructing Cipher_State using init_with_server_hello().
 * In this state the handshake traffic secrets are available. The state can then be further
 * advanced using advance_with_server_finished().
 *                                     *
 *                                     |
 *                                     v
 *                           0 -> HKDF-Extract = Master Secret
 *                                     |
 *                                     +-----> Derive-Secret(., "c ap traffic",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = client_application_traffic_secret_0
 *                                     |
 *                                     +-----> Derive-Secret(., "s ap traffic",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = server_application_traffic_secret_0
 *                                     |
 *                                     +-----> Derive-Secret(., "exp master",
 *                                     |                     ClientHello...server Finished)
 *                                     |                     = exporter_master_secret
 *                                     *
 *                         STATE APPLICATION TRAFFIC
 * This state is reached by calling advance_with_server_finished(). The state can then be further
 * advanced using advance_with_client_finished().
 *                                     *
 *                                     |
 *                                     +-----> Derive-Secret(., "res master",
 *                                                           ClientHello...client Finished)
 *                                                           = resumption_master_secret
 *                             STATE COMPLETED
 */

#include <limits>

#include <botan/internal/tls_cipher_state.h>

#include <botan/aead.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/hash.h>
#include <botan/tls_magic.h>

#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/loadstor.h>

using namespace Botan;
using namespace Botan::TLS;

std::unique_ptr<Cipher_State> Cipher_State::init_with_server_hello(
   const Connection_Side side,
   secure_vector<uint8_t>&& shared_secret,
   const Ciphersuite& cipher,
   const Transcript_Hash& transcript_hash)
   {
   auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(side, cipher));
   cs->advance_without_psk();
   cs->advance_with_server_hello(std::move(shared_secret), transcript_hash);
   return cs;
   }

void Cipher_State::advance_with_server_finished(const Transcript_Hash& transcript_hash)
   {
   BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);

   m_finished_key.clear();
   m_peer_finished_key.clear();

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   derive_traffic_secrets(
      derive_secret(master_secret, "c ap traffic", transcript_hash),
      derive_secret(master_secret, "s ap traffic", transcript_hash));

   m_state = State::ApplicationTraffic;
   }

void Cipher_State::advance_with_client_finished(const Transcript_Hash& transcript_hash)
   {
   BOTAN_ASSERT_NOMSG(m_state == State::ApplicationTraffic);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   m_resumption_master_secret = derive_secret(master_secret, "res master", transcript_hash);

   // This was the final state change; the salt is no longer needed.
   m_salt.clear();

   m_state = State::Completed;
   }

std::vector<uint8_t> Cipher_State::current_nonce(const uint64_t seq_no, const secure_vector<uint8_t>& iv) const
   {
   // RFC 8446 5.3
   //    The per-record nonce for the AEAD construction is formed as follows:
   //
   //    1.  The 64-bit record sequence number is encoded in network byte
   //        order and padded to the left with zeros to iv_length.
   //
   //    2.  The padded sequence number is XORed with either the static
   //        client_write_iv or server_write_iv (depending on the role).
   std::vector<uint8_t> nonce(m_nonce_length);
   store_be(seq_no, nonce.data() + (m_nonce_length-sizeof(seq_no)));
   xor_buf(nonce, iv.data(), iv.size());
   return nonce;
   }

uint64_t Cipher_State::encrypt_record_fragment(const std::vector<uint8_t>& header, secure_vector<uint8_t>& fragment)
   {
   m_encrypt->set_key(m_write_key);
   m_encrypt->set_associated_data_vec(header);
   m_encrypt->start(current_nonce(m_write_seq_no, m_write_iv));
   m_encrypt->finish(fragment);

   return m_write_seq_no++;
   }

uint64_t Cipher_State::decrypt_record_fragment(const std::vector<uint8_t>& header,
      secure_vector<uint8_t>& encrypted_fragment)
   {
   m_decrypt->set_key(m_peer_write_key);
   m_decrypt->set_associated_data_vec(header);
   m_decrypt->start(current_nonce(m_peer_write_seq_no, m_peer_write_iv));

   try
      {
      m_decrypt->finish(encrypted_fragment);
      }
   catch(const Decoding_Error& ex)
      {
      // Decoding_Error is thrown by AEADs if the provided cipher text was
      // too short to hold an authentication tag. We are treating this as
      // an Invalid_Authentication_Tag so that the TLS channel will react
      // with an BAD_RECORD_MAC alert as specified in RFC 8446 5.2.
      throw Invalid_Authentication_Tag(ex.what());
      }

   return m_peer_write_seq_no++;
   }

size_t Cipher_State::encrypt_output_length(const size_t input_length) const
   {
   return m_encrypt->output_length(input_length);
   }

std::vector<uint8_t> Cipher_State::finished_mac(const Transcript_Hash& transcript_hash) const
   {
   BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_finished_key);
   hmac.update(transcript_hash);
   return hmac.final_stdvec();
   }

bool Cipher_State::verify_peer_finished_mac(const Transcript_Hash& transcript_hash,
      const std::vector<uint8_t>& peer_mac) const
   {
   BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_peer_finished_key);
   hmac.update(transcript_hash);
   return hmac.verify_mac(peer_mac);
   }

secure_vector<uint8_t> Cipher_State::psk(const std::vector<uint8_t>& nonce) const
   {
   BOTAN_ASSERT_NOMSG(m_state == State::Completed);

   return derive_secret(m_resumption_master_secret, "resumption", nonce);
   }

namespace {

std::unique_ptr<MessageAuthenticationCode> create_hmac(const Ciphersuite& cipher)
   {
   return std::make_unique<HMAC>(HashFunction::create_or_throw(cipher.prf_algo()));
   }

// The nonce length is specified as the maximum of 8 and the cipher mode's
// minimum nonce length (see RFC 8446 5.3).
size_t nonce_len_for_cipher_suite(const Ciphersuite& suite)
   {
   // TODO: We understood from the RFC that ChaCha20 should be 8 rather than
   // 12, but that didn't work. Check again.
   switch(suite.ciphersuite_code())
      {
      case 0x1301:   // AES_128_GCM_SHA256
      case 0x1302:   // AES_256_GCM_SHA384
         return 12;
      case 0x1303:   // CHACHA20_POLY1305_SHA256
         return 12;
      case 0x1304:   // AES_128_CCM_SHA256
      case 0x1305:   // AES_128_CCM_8_SHA256
         return 12;
      default:
         BOTAN_ASSERT(false, "Cipher suite is not supported for TLS 1.3");
      };
   }
}

Cipher_State::Cipher_State(Connection_Side whoami, const Ciphersuite& cipher)
   : m_state(State::Uninitialized)
   , m_connection_side(whoami)
   , m_encrypt(AEAD_Mode::create(cipher.cipher_algo(), ENCRYPTION))
   , m_decrypt(AEAD_Mode::create(cipher.cipher_algo(), DECRYPTION))
   , m_nonce_length(nonce_len_for_cipher_suite(cipher))
   , m_extract(std::make_unique<HKDF_Extract>(create_hmac(cipher)))
   , m_expand(std::make_unique<HKDF_Expand>(create_hmac(cipher)))
   , m_hash(HashFunction::create_or_throw(cipher.prf_algo()))
   , m_salt(m_hash->output_length(), 0x00)
   , m_write_seq_no(0)
   , m_peer_write_seq_no(0) {}

Cipher_State::~Cipher_State() = default;

void Cipher_State::advance_without_psk()
   {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);

   const auto early_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));
   m_salt = derive_secret(early_secret, "derived", empty_hash());

   m_state = State::EarlyTraffic;
   }

void Cipher_State::advance_with_server_hello(secure_vector<uint8_t>&& shared_secret,
      const Transcript_Hash& transcript_hash)
   {
   BOTAN_ASSERT_NOMSG(m_state == State::EarlyTraffic);

   const auto handshake_secret = hkdf_extract(std::move(shared_secret));

   derive_traffic_secrets(
      derive_secret(handshake_secret, "c hs traffic", transcript_hash),
      derive_secret(handshake_secret, "s hs traffic", transcript_hash),
      true);

   m_salt = derive_secret(handshake_secret, "derived", empty_hash());

   m_state = State::HandshakeTraffic;
   }

void Cipher_State::derive_traffic_secrets(secure_vector<uint8_t> client_traffic_secret,
      secure_vector<uint8_t> server_traffic_secret,
      const bool handshake_traffic_secrets)
   {
   const auto& traffic_secret =
      (m_connection_side == Connection_Side::CLIENT)
      ? client_traffic_secret
      : server_traffic_secret;

   const auto& peer_traffic_secret =
      (m_connection_side == Connection_Side::SERVER)
      ? client_traffic_secret
      : server_traffic_secret;

   m_write_key = hkdf_expand_label(traffic_secret, "key", {}, m_encrypt->minimum_keylength());
   m_peer_write_key = hkdf_expand_label(peer_traffic_secret, "key", {}, m_decrypt->minimum_keylength());

   m_write_iv = hkdf_expand_label(traffic_secret, "iv", {}, m_nonce_length);
   m_peer_write_iv = hkdf_expand_label(peer_traffic_secret, "iv", {}, m_nonce_length);

   m_write_seq_no = 0;
   m_peer_write_seq_no = 0;

   if(handshake_traffic_secrets)
      {
      // Key derivation for the MAC in the "Finished" handshake message as described in RFC 8446 4.4.4
      // (will be cleared in advance_with_server_finished())
      m_finished_key = hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
      m_peer_finished_key = hkdf_expand_label(peer_traffic_secret, "finished", {}, m_hash->output_length());
      }
   }

secure_vector<uint8_t> Cipher_State::hkdf_extract(secure_vector<uint8_t>&& ikm) const
   {
   return m_extract->derive_key(m_hash->output_length(), ikm, m_salt, std::vector<uint8_t>());
   }

secure_vector<uint8_t> Cipher_State::hkdf_expand_label(
   const secure_vector<uint8_t>& secret,
   std::string                   label,
   const std::vector<uint8_t>&   context,
   const size_t                  length) const
   {
   // assemble (serialized) HkdfLabel
   secure_vector<uint8_t> hkdf_label;
   hkdf_label.reserve(2 /* length */ + (label.size() + 6 /* 'tls13 ' */ + 1 /* length field*/) +
                      (context.size() + 1 /* length field*/));

   // length
   BOTAN_ASSERT_NOMSG(length <= std::numeric_limits<uint16_t>::max());
   const auto len = static_cast<uint16_t>(length);
   hkdf_label.push_back(get_byte<0>(len));
   hkdf_label.push_back(get_byte<1>(len));

   // label
   const std::string prefix = "tls13 ";
   hkdf_label.push_back(prefix.size() + label.size());
   hkdf_label.insert(hkdf_label.end(), prefix.cbegin(), prefix.cend());
   hkdf_label.insert(hkdf_label.end(), label.cbegin(), label.cend());

   // context
   hkdf_label.push_back(context.size());
   hkdf_label.insert(hkdf_label.end(), context.cbegin(), context.cend());

   // HKDF-Expand
   return m_expand->derive_key(length, secret, hkdf_label, std::vector<uint8_t>() /* just pleasing botan's interface */);
   }

secure_vector<uint8_t> Cipher_State::derive_secret(
   const secure_vector<uint8_t>& secret,
   std::string label,
   const Transcript_Hash& messages_hash) const
   {
   return hkdf_expand_label(secret, label, messages_hash, m_hash->output_length());
   }

std::vector<uint8_t> Cipher_State::empty_hash() const
   {
   m_hash->update("");
   return m_hash->final_stdvec();
   }
