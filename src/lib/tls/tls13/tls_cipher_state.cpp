/*
* TLS cipher state implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
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
#include <utility>

#include <botan/internal/tls_cipher_state.h>

#include <botan/aead.h>
#include <botan/assert.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/hash.h>
#include <botan/tls_magic.h>

#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/loadstor.h>

namespace Botan::TLS {

namespace {
// RFC 8446 5.3
//    Each AEAD algorithm will specify a range of possible lengths for the
//    per-record nonce, from N_MIN bytes to N_MAX bytes of input [RFC5116].
//    The length of the TLS per-record nonce (iv_length) is set to the
//    larger of 8 bytes and N_MIN for the AEAD algorithm (see [RFC5116],
//    Section 4).
//
// N_MIN is 12 for AES_GCM and AES_CCM as per RFC 5116 and also 12 for ChaCha20 per RFC 8439.
constexpr size_t NONCE_LENGTH = 12;
}

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

   zap(m_finished_key);
   zap(m_peer_finished_key);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   auto client_application_traffic_secret = derive_secret(master_secret, "c ap traffic", transcript_hash);
   auto server_application_traffic_secret = derive_secret(master_secret, "s ap traffic", transcript_hash);

   if(m_connection_side == Connection_Side::SERVER)
      {
      derive_read_traffic_key(client_application_traffic_secret);
      derive_write_traffic_key(server_application_traffic_secret);
      m_read_application_traffic_secret = std::move(client_application_traffic_secret);
      m_write_application_traffic_secret      = std::move(server_application_traffic_secret);
      }
   else
      {
      derive_read_traffic_key(server_application_traffic_secret);
      derive_write_traffic_key(client_application_traffic_secret);
      m_read_application_traffic_secret = std::move(server_application_traffic_secret);
      m_write_application_traffic_secret      = std::move(client_application_traffic_secret);
      }

   m_exporter_master_secret = derive_secret(master_secret, "exp master", transcript_hash);

   m_state = State::ApplicationTraffic;
   }

void Cipher_State::advance_with_client_finished(const Transcript_Hash& transcript_hash)
   {
   BOTAN_ASSERT_NOMSG(m_state == State::ApplicationTraffic);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   m_resumption_master_secret = derive_secret(master_secret, "res master", transcript_hash);

   // This was the final state change; the salt is no longer needed.
   zap(m_salt);

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
   std::vector<uint8_t> nonce(NONCE_LENGTH);
   store_be(seq_no, nonce.data() + (NONCE_LENGTH-sizeof(seq_no)));
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
   BOTAN_ARG_CHECK(encrypted_fragment.size() >= m_decrypt->minimum_final_size(),
         "fragment too short to decrypt");

   m_decrypt->set_key(m_read_key);
   m_decrypt->set_associated_data_vec(header);
   m_decrypt->start(current_nonce(m_read_seq_no, m_read_iv));

   m_decrypt->finish(encrypted_fragment);

   return m_read_seq_no++;
   }

size_t Cipher_State::encrypt_output_length(const size_t input_length) const
   {
   return m_encrypt->output_length(input_length);
   }

size_t Cipher_State::decrypt_output_length(const size_t input_length) const
   {
   return m_decrypt->output_length(input_length);
   }

size_t Cipher_State::minimum_decryption_input_length() const
   {
   return m_decrypt->minimum_final_size();
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


secure_vector<uint8_t> Cipher_State::export_key(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   BOTAN_ASSERT_NOMSG(can_export_keys());

   m_hash->update(context);
   const auto context_hash = m_hash->final_stdvec();
   return hkdf_expand_label(derive_secret(m_exporter_master_secret, label, empty_hash()),
                            "exporter", context_hash, length);
   }


namespace {

std::unique_ptr<MessageAuthenticationCode> create_hmac(const Ciphersuite& cipher)
   {
   return std::make_unique<HMAC>(HashFunction::create_or_throw(cipher.prf_algo()));
   }

}

Cipher_State::Cipher_State(Connection_Side whoami, const Ciphersuite& cipher)
   : m_state(State::Uninitialized)
   , m_connection_side(whoami)
   , m_encrypt(AEAD_Mode::create(cipher.cipher_algo(), ENCRYPTION))
   , m_decrypt(AEAD_Mode::create(cipher.cipher_algo(), DECRYPTION))
   , m_extract(std::make_unique<HKDF_Extract>(create_hmac(cipher)))
   , m_expand(std::make_unique<HKDF_Expand>(create_hmac(cipher)))
   , m_hash(HashFunction::create_or_throw(cipher.prf_algo()))
   , m_salt(m_hash->output_length(), 0x00)
   , m_write_seq_no(0)
   , m_read_seq_no(0) {}

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

   const auto client_handshake_traffic_secret = derive_secret(handshake_secret, "c hs traffic", transcript_hash);
   const auto server_handshake_traffic_secret = derive_secret(handshake_secret, "s hs traffic", transcript_hash);

   if(m_connection_side == Connection_Side::SERVER)
      {
      derive_read_traffic_key(client_handshake_traffic_secret, true);
      derive_write_traffic_key(server_handshake_traffic_secret, true);
      }
   else
      {
      derive_read_traffic_key(server_handshake_traffic_secret, true);
      derive_write_traffic_key(client_handshake_traffic_secret, true);
      }

   m_salt = derive_secret(handshake_secret, "derived", empty_hash());

   m_state = State::HandshakeTraffic;
   }

void Cipher_State::derive_write_traffic_key(const secure_vector<uint8_t>& traffic_secret,
      const bool handshake_traffic_secret)
   {
   m_write_key    = hkdf_expand_label(traffic_secret, "key", {}, m_encrypt->minimum_keylength());
   m_write_iv     = hkdf_expand_label(traffic_secret, "iv", {}, NONCE_LENGTH);
   m_write_seq_no = 0;

   if(handshake_traffic_secret)
      {
      // Key derivation for the MAC in the "Finished" handshake message as described in RFC 8446 4.4.4
      // (will be cleared in advance_with_server_finished())
      m_finished_key = hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
      }
   }

void Cipher_State::derive_read_traffic_key(const secure_vector<uint8_t>& traffic_secret,
      const bool handshake_traffic_secret)
   {
   m_read_key    = hkdf_expand_label(traffic_secret, "key", {}, m_encrypt->minimum_keylength());
   m_read_iv     = hkdf_expand_label(traffic_secret, "iv", {}, NONCE_LENGTH);
   m_read_seq_no = 0;

   if(handshake_traffic_secret)
      {
      // Key derivation for the MAC in the "Finished" handshake message as described in RFC 8446 4.4.4
      // (will be cleared in advance_with_server_finished())
      m_peer_finished_key = hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
      }
   }

secure_vector<uint8_t> Cipher_State::hkdf_extract(secure_vector<uint8_t>&& ikm) const
   {
   return m_extract->derive_key(m_hash->output_length(), ikm, m_salt, std::vector<uint8_t>());
   }

secure_vector<uint8_t> Cipher_State::hkdf_expand_label(
   const secure_vector<uint8_t>& secret,
   const std::string&            label,
   const std::vector<uint8_t>&   context,
   const size_t                  length) const
   {
   // assemble (serialized) HkdfLabel
   secure_vector<uint8_t> hkdf_label;
   hkdf_label.reserve(2 /* length */ +
                      (label.size() +
                       6 /* 'tls13 ' */ +
                       1 /* length field*/) +
                      (context.size() +
                       1 /* length field*/));

   // length
   BOTAN_ARG_CHECK(length <= std::numeric_limits<uint16_t>::max(), "invalid length");
   const auto len = static_cast<uint16_t>(length);
   hkdf_label.push_back(get_byte<0>(len));
   hkdf_label.push_back(get_byte<1>(len));

   // label
   const std::string prefix = "tls13 ";
   BOTAN_ARG_CHECK(prefix.size() + label.size() <= 255, "label too large");
   hkdf_label.push_back(static_cast<uint8_t>(prefix.size() + label.size()));
   hkdf_label.insert(hkdf_label.end(), prefix.cbegin(), prefix.cend());
   hkdf_label.insert(hkdf_label.end(), label.cbegin(), label.cend());

   // context
   BOTAN_ARG_CHECK(context.size() <= 255, "context too large");
   hkdf_label.push_back(static_cast<uint8_t>(context.size()));
   hkdf_label.insert(hkdf_label.end(), context.cbegin(), context.cend());

   // HKDF-Expand
   return m_expand->derive_key(length, secret, hkdf_label, std::vector<uint8_t>() /* just pleasing botan's interface */);
   }

secure_vector<uint8_t> Cipher_State::derive_secret(
   const secure_vector<uint8_t>& secret,
   const std::string&            label,
   const Transcript_Hash&        messages_hash) const
   {
   return hkdf_expand_label(secret, label, messages_hash, m_hash->output_length());
   }

std::vector<uint8_t> Cipher_State::empty_hash() const
   {
   m_hash->update("");
   return m_hash->final_stdvec();
   }

void Cipher_State::update_read_keys()
   {
   BOTAN_ASSERT_NOMSG(m_state == State::ApplicationTraffic ||
                      m_state == State::Completed);

   m_read_application_traffic_secret =
      hkdf_expand_label(m_read_application_traffic_secret, "traffic upd", {}, m_hash->output_length());

   derive_read_traffic_key(m_read_application_traffic_secret);
   }

void Cipher_State::update_write_keys()
   {
   BOTAN_ASSERT_NOMSG(m_state == State::ApplicationTraffic ||
                      m_state == State::Completed);
   m_write_application_traffic_secret =
      hkdf_expand_label(m_write_application_traffic_secret, "traffic upd", {}, m_hash->output_length());

   derive_write_traffic_key(m_write_application_traffic_secret);
   }

void Cipher_State::clear_read_keys()
   {
   zap(m_read_key);
   zap(m_read_iv);
   zap(m_read_application_traffic_secret);
   }

void Cipher_State::clear_write_keys()
   {
   zap(m_write_key);
   zap(m_write_iv);
   zap(m_write_application_traffic_secret);
   }

}  // namespace Botan::TLS
