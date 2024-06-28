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
 *                              STATE PSK BINDER
 * This state is reached by constructing the Cipher_State using init_with_psk().
 * The state can then be further advanced using advance_with_client_hello() once
 * the initial Client Hello is fully generated.
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
 * This state is reached by calling advance_with_client_hello().
 * In this state the early data traffic secrets are available. TODO: implement early data.
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
 * This state is reached by constructing Cipher_State using init_with_server_hello() or
 * advance_with_server_hello(). In this state the handshake traffic secrets are available.
 * The state can then be further advanced using advance_with_server_finished().
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
 *                      STATE SERVER APPLICATION TRAFFIC
 * This state is reached by calling advance_with_server_finished(). It allows the server
 * to send application traffic and the client to receive it. The opposite direction is not
 * yet possible in this state. The state can then be further advanced using
 * advance_with_client_finished().
 *                                     *
 *                                     |
 *                                     +-----> Derive-Secret(., "res master",
 *                                                           ClientHello...client Finished)
 *                                                           = resumption_master_secret
 *                             STATE COMPLETED
 * Once this state is reached the handshake is finished, both client and server can exchange
 * application data and no further cipher state advances are possible.
 */

#include <limits>
#include <utility>

#include <botan/internal/tls_cipher_state.h>

#include <botan/aead.h>
#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_magic.h>

#include <botan/internal/fmt.h>
#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_channel_impl_13.h>

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
}  // namespace

std::unique_ptr<Cipher_State> Cipher_State::init_with_server_hello(const Connection_Side side,
                                                                   secure_vector<uint8_t>&& shared_secret,
                                                                   const Ciphersuite& cipher,
                                                                   const Transcript_Hash& transcript_hash,
                                                                   const Secret_Logger& loggger) {
   auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(side, cipher.prf_algo()));
   cs->advance_without_psk();
   cs->advance_with_server_hello(cipher, std::move(shared_secret), transcript_hash, loggger);
   return cs;
}

std::unique_ptr<Cipher_State> Cipher_State::init_with_psk(const Connection_Side side,
                                                          const Cipher_State::PSK_Type type,
                                                          secure_vector<uint8_t>&& psk,
                                                          std::string_view prf_algo) {
   auto cs = std::unique_ptr<Cipher_State>(new Cipher_State(side, prf_algo));
   cs->advance_with_psk(type, std::move(psk));
   return cs;
}

void Cipher_State::advance_with_client_hello(const Transcript_Hash& transcript_hash, const Secret_Logger& loggger) {
   BOTAN_ASSERT_NOMSG(m_state == State::PskBinder);

   zap(m_binder_key);

   // TODO: Currently 0-RTT is not yet implemented, hence we don't derive the
   //       early traffic secret for now.
   //
   // const auto client_early_traffic_secret = derive_secret(m_early_secret, "c e traffic", transcript_hash);
   // derive_write_traffic_key(client_early_traffic_secret);

   m_exporter_master_secret = derive_secret(m_early_secret, "e exp master", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label
   //    "EARLY_EXPORTER_MASTER_SECRET" to identify the secret that is using for
   //    early exporters
   loggger.maybe_log_secret("EARLY_EXPORTER_MASTER_SECRET", m_exporter_master_secret);

   m_salt = derive_secret(m_early_secret, "derived", empty_hash());
   zap(m_early_secret);

   m_state = State::EarlyTraffic;
}

void Cipher_State::advance_with_server_finished(const Transcript_Hash& transcript_hash, const Secret_Logger& loggger) {
   BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   auto client_application_traffic_secret = derive_secret(master_secret, "c ap traffic", transcript_hash);
   auto server_application_traffic_secret = derive_secret(master_secret, "s ap traffic", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label "CLIENT_TRAFFIC_SECRET_0"
   //    and "SERVER_TRAFFIC_SECRET_0" to identify the secrets are using to
   //    protect the connection.
   loggger.maybe_log_secret("CLIENT_TRAFFIC_SECRET_0", client_application_traffic_secret);
   loggger.maybe_log_secret("SERVER_TRAFFIC_SECRET_0", server_application_traffic_secret);

   // Note: the secrets for processing client's application data
   //       are not derived before the client's Finished message
   //       was seen and the handshake can be considered finished.
   if(m_connection_side == Connection_Side::Server) {
      derive_write_traffic_key(server_application_traffic_secret);
      m_read_application_traffic_secret = std::move(client_application_traffic_secret);
      m_write_application_traffic_secret = std::move(server_application_traffic_secret);
   } else {
      derive_read_traffic_key(server_application_traffic_secret);
      m_read_application_traffic_secret = std::move(server_application_traffic_secret);
      m_write_application_traffic_secret = std::move(client_application_traffic_secret);
   }

   m_exporter_master_secret = derive_secret(master_secret, "exp master", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label "EXPORTER_SECRET" to
   //    identify the secret that is used in generating exporters(rfc8446
   //    Section 7.5).
   loggger.maybe_log_secret("EXPORTER_SECRET", m_exporter_master_secret);

   m_state = State::ServerApplicationTraffic;
}

void Cipher_State::advance_with_client_finished(const Transcript_Hash& transcript_hash) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic);

   zap(m_finished_key);
   zap(m_peer_finished_key);

   // With the client's Finished message, the handshake is complete and
   // we can process client application data.
   if(m_connection_side == Connection_Side::Server) {
      derive_read_traffic_key(m_read_application_traffic_secret);
   } else {
      derive_write_traffic_key(m_write_application_traffic_secret);
   }

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   m_resumption_master_secret = derive_secret(master_secret, "res master", transcript_hash);

   // This was the final state change; the salt is no longer needed.
   zap(m_salt);

   m_state = State::Completed;
}

namespace {

auto current_nonce(const uint64_t seq_no, std::span<const uint8_t> iv) {
   // RFC 8446 5.3
   //    The per-record nonce for the AEAD construction is formed as follows:
   //
   //    1.  The 64-bit record sequence number is encoded in network byte
   //        order and padded to the left with zeros to iv_length.
   //
   //    2.  The padded sequence number is XORed with either the static
   //        client_write_iv or server_write_iv (depending on the role).
   std::array<uint8_t, NONCE_LENGTH> nonce{};
   store_be(std::span{nonce}.last<sizeof(seq_no)>(), seq_no);
   xor_buf(nonce, iv);
   return nonce;
}

}  // namespace

uint64_t Cipher_State::encrypt_record_fragment(const std::vector<uint8_t>& header, secure_vector<uint8_t>& fragment) {
   BOTAN_ASSERT_NONNULL(m_encrypt);

   m_encrypt->set_key(m_write_key);
   m_encrypt->set_associated_data(header);
   m_encrypt->start(current_nonce(m_write_seq_no, m_write_iv));
   m_encrypt->finish(fragment);

   return m_write_seq_no++;
}

uint64_t Cipher_State::decrypt_record_fragment(const std::vector<uint8_t>& header,
                                               secure_vector<uint8_t>& encrypted_fragment) {
   BOTAN_ASSERT_NONNULL(m_decrypt);
   BOTAN_ARG_CHECK(encrypted_fragment.size() >= m_decrypt->minimum_final_size(), "fragment too short to decrypt");

   m_decrypt->set_key(m_read_key);
   m_decrypt->set_associated_data(header);
   m_decrypt->start(current_nonce(m_read_seq_no, m_read_iv));

   m_decrypt->finish(encrypted_fragment);

   return m_read_seq_no++;
}

size_t Cipher_State::encrypt_output_length(const size_t input_length) const {
   BOTAN_ASSERT_NONNULL(m_encrypt);
   return m_encrypt->output_length(input_length);
}

size_t Cipher_State::decrypt_output_length(const size_t input_length) const {
   BOTAN_ASSERT_NONNULL(m_decrypt);
   return m_decrypt->output_length(input_length);
}

size_t Cipher_State::minimum_decryption_input_length() const {
   BOTAN_ASSERT_NONNULL(m_decrypt);
   return m_decrypt->minimum_final_size();
}

bool Cipher_State::must_expect_unprotected_alert_traffic() const {
   // Client side:
   //   After successfully receiving a Server Hello we expect servers to send
   //   alerts as protected records only, just like they start protecting their
   //   handshake data at this point.
   if(m_connection_side == Connection_Side::Client && m_state == State::EarlyTraffic) {
      return true;
   }

   // Server side:
   //   Servers must expect clients to send unprotected alerts during the hand-
   //   shake. In particular, in the response to the server's first protected
   //   flight. We don't expect the client to send alerts protected under the
   //   early traffic secret.
   //
   // TODO: when implementing PSK and/or early data for the server, we might
   //       need to reconsider this decision.
   if(m_connection_side == Connection_Side::Server &&
      (m_state == State::HandshakeTraffic || m_state == State::ServerApplicationTraffic)) {
      return true;
   }

   return false;
}

bool Cipher_State::can_encrypt_application_traffic() const {
   // TODO: when implementing early traffic (0-RTT) this will likely need
   //       to allow `State::EarlyTraffic`.

   if(m_connection_side == Connection_Side::Client && m_state != State::Completed) {
      return false;
   }

   if(m_connection_side == Connection_Side::Server && m_state != State::ServerApplicationTraffic &&
      m_state != State::Completed) {
      return false;
   }

   return !m_write_key.empty() && !m_write_iv.empty();
}

bool Cipher_State::can_decrypt_application_traffic() const {
   // TODO: when implementing early traffic (0-RTT) this will likely need
   //       to allow `State::EarlyTraffic`.

   if(m_connection_side == Connection_Side::Client && m_state != State::ServerApplicationTraffic &&
      m_state != State::Completed) {
      return false;
   }

   if(m_connection_side == Connection_Side::Server && m_state != State::Completed) {
      return false;
   }

   return !m_read_key.empty() && !m_read_iv.empty();
}

std::string Cipher_State::hash_algorithm() const {
   BOTAN_ASSERT_NONNULL(m_hash);
   return m_hash->name();
}

bool Cipher_State::is_compatible_with(const Ciphersuite& cipher) const {
   if(!cipher.usable_in_version(Protocol_Version::TLS_V13)) {
      return false;
   }

   if(hash_algorithm() != cipher.prf_algo()) {
      return false;
   }

   BOTAN_ASSERT_NOMSG((m_encrypt == nullptr) == (m_decrypt == nullptr));
   // TODO: Find a better way to check that the instantiated cipher algorithm
   //       is compatible with the one required by the cipher suite.
   // AEAD_Mode::create() sets defaults the tag length to 16 which is then
   // reported via AEAD_Mode::name() and hinders the trivial string comparison.
   if(m_encrypt && m_encrypt->name() != cipher.cipher_algo() && m_encrypt->name() != cipher.cipher_algo() + "(16)") {
      return false;
   }

   return true;
}

std::vector<uint8_t> Cipher_State::psk_binder_mac(
   const Transcript_Hash& transcript_hash_with_truncated_client_hello) const {
   BOTAN_ASSERT_NOMSG(m_state == State::PskBinder);

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_binder_key);
   hmac.update(transcript_hash_with_truncated_client_hello);
   return hmac.final_stdvec();
}

std::vector<uint8_t> Cipher_State::finished_mac(const Transcript_Hash& transcript_hash) const {
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Server || m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Client || m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NOMSG(!m_finished_key.empty());

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_finished_key);
   hmac.update(transcript_hash);
   return hmac.final_stdvec();
}

bool Cipher_State::verify_peer_finished_mac(const Transcript_Hash& transcript_hash,
                                            const std::vector<uint8_t>& peer_mac) const {
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Server || m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Client || m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NOMSG(!m_peer_finished_key.empty());

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_peer_finished_key);
   hmac.update(transcript_hash);
   return hmac.verify_mac(peer_mac);
}

secure_vector<uint8_t> Cipher_State::psk(const Ticket_Nonce& nonce) const {
   BOTAN_ASSERT_NOMSG(m_state == State::Completed);

   return derive_secret(m_resumption_master_secret, "resumption", nonce.get());
}

Ticket_Nonce Cipher_State::next_ticket_nonce() {
   BOTAN_STATE_CHECK(m_state == State::Completed);
   if(m_ticket_nonce == std::numeric_limits<decltype(m_ticket_nonce)>::max()) {
      throw Botan::Invalid_State("ticket nonce pool exhausted");
   }

   Ticket_Nonce retval(std::vector<uint8_t>(sizeof(m_ticket_nonce)));
   store_be(m_ticket_nonce++, retval.data());

   return retval;
}

secure_vector<uint8_t> Cipher_State::export_key(std::string_view label, std::string_view context, size_t length) const {
   BOTAN_ASSERT_NOMSG(can_export_keys());

   m_hash->update(context);
   const auto context_hash = m_hash->final_stdvec();
   return hkdf_expand_label(
      derive_secret(m_exporter_master_secret, label, empty_hash()), "exporter", context_hash, length);
}

namespace {

std::unique_ptr<MessageAuthenticationCode> create_hmac(std::string_view hash) {
   return std::make_unique<HMAC>(HashFunction::create_or_throw(hash));
}

}  // namespace

Cipher_State::Cipher_State(Connection_Side whoami, std::string_view hash_function) :
      m_state(State::Uninitialized),
      m_connection_side(whoami),
      m_extract(std::make_unique<HKDF_Extract>(create_hmac(hash_function))),
      m_expand(std::make_unique<HKDF_Expand>(create_hmac(hash_function))),
      m_hash(HashFunction::create_or_throw(hash_function)),
      m_salt(m_hash->output_length(), 0x00),
      m_write_seq_no(0),
      m_read_seq_no(0),
      m_write_key_update_count(0),
      m_read_key_update_count(0),
      m_ticket_nonce(0) {}

Cipher_State::~Cipher_State() = default;

void Cipher_State::advance_without_psk() {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);

   // We are not using `m_early_secret` here because the secret won't be needed
   // in any further state advancement methods.
   const auto early_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));
   m_salt = derive_secret(early_secret, "derived", empty_hash());

   // Without PSK we skip the `PskBinder` state and go right to `EarlyTraffic`.
   m_state = State::EarlyTraffic;
}

void Cipher_State::advance_with_psk(PSK_Type type, secure_vector<uint8_t>&& psk) {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);

   m_early_secret = hkdf_extract(std::move(psk));

   const char* binder_label = (type == PSK_Type::Resumption) ? "res binder" : "ext binder";

   // RFC 8446 4.2.11.2
   //    The PskBinderEntry is computed in the same way as the Finished message
   //    [...] but with the BaseKey being the binder_key derived via the key
   //    schedule from the corresponding PSK which is being offered.
   //
   // Hence we are doing the binder key derivation and expansion in one go.
   const auto binder_key = derive_secret(m_early_secret, binder_label, empty_hash());
   m_binder_key = hkdf_expand_label(binder_key, "finished", {}, m_hash->output_length());

   m_state = State::PskBinder;
}

void Cipher_State::advance_with_server_hello(const Ciphersuite& cipher,
                                             secure_vector<uint8_t>&& shared_secret,
                                             const Transcript_Hash& transcript_hash,
                                             const Secret_Logger& loggger) {
   BOTAN_ASSERT_NOMSG(m_state == State::EarlyTraffic);
   BOTAN_ASSERT_NOMSG(!m_encrypt);
   BOTAN_ASSERT_NOMSG(!m_decrypt);
   BOTAN_STATE_CHECK(is_compatible_with(cipher));

   m_encrypt = AEAD_Mode::create_or_throw(cipher.cipher_algo(), Cipher_Dir::Encryption);
   m_decrypt = AEAD_Mode::create_or_throw(cipher.cipher_algo(), Cipher_Dir::Decryption);

   const auto handshake_secret = hkdf_extract(std::move(shared_secret));

   const auto client_handshake_traffic_secret = derive_secret(handshake_secret, "c hs traffic", transcript_hash);
   const auto server_handshake_traffic_secret = derive_secret(handshake_secret, "s hs traffic", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label
   //    "CLIENT_HANDSHAKE_TRAFFIC_SECRET" and "SERVER_HANDSHAKE_TRAFFIC_SECRET"
   //    to identify the secrets are using to protect handshake messages.
   loggger.maybe_log_secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_handshake_traffic_secret);
   loggger.maybe_log_secret("SERVER_HANDSHAKE_TRAFFIC_SECRET", server_handshake_traffic_secret);

   if(m_connection_side == Connection_Side::Server) {
      derive_read_traffic_key(client_handshake_traffic_secret, true);
      derive_write_traffic_key(server_handshake_traffic_secret, true);
   } else {
      derive_read_traffic_key(server_handshake_traffic_secret, true);
      derive_write_traffic_key(client_handshake_traffic_secret, true);
   }

   m_salt = derive_secret(handshake_secret, "derived", empty_hash());

   m_state = State::HandshakeTraffic;
}

void Cipher_State::derive_write_traffic_key(const secure_vector<uint8_t>& traffic_secret,
                                            const bool handshake_traffic_secret) {
   BOTAN_ASSERT_NONNULL(m_encrypt);

   m_write_key = hkdf_expand_label(traffic_secret, "key", {}, m_encrypt->minimum_keylength());
   m_write_iv = hkdf_expand_label(traffic_secret, "iv", {}, NONCE_LENGTH);
   m_write_seq_no = 0;

   if(handshake_traffic_secret) {
      // Key derivation for the MAC in the "Finished" handshake message as described in RFC 8446 4.4.4
      // (will be cleared in advance_with_server_finished())
      m_finished_key = hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
   }
}

void Cipher_State::derive_read_traffic_key(const secure_vector<uint8_t>& traffic_secret,
                                           const bool handshake_traffic_secret) {
   BOTAN_ASSERT_NONNULL(m_encrypt);

   m_read_key = hkdf_expand_label(traffic_secret, "key", {}, m_encrypt->minimum_keylength());
   m_read_iv = hkdf_expand_label(traffic_secret, "iv", {}, NONCE_LENGTH);
   m_read_seq_no = 0;

   if(handshake_traffic_secret) {
      // Key derivation for the MAC in the "Finished" handshake message as described in RFC 8446 4.4.4
      // (will be cleared in advance_with_client_finished())
      m_peer_finished_key = hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
   }
}

secure_vector<uint8_t> Cipher_State::hkdf_extract(std::span<const uint8_t> ikm) const {
   return m_extract->derive_key(m_hash->output_length(), ikm, m_salt, std::vector<uint8_t>());
}

secure_vector<uint8_t> Cipher_State::hkdf_expand_label(const secure_vector<uint8_t>& secret,
                                                       std::string_view label,
                                                       const std::vector<uint8_t>& context,
                                                       const size_t length) const {
   // assemble (serialized) HkdfLabel
   secure_vector<uint8_t> hkdf_label;
   hkdf_label.reserve(2 /* length */ + (label.size() + 6 /* 'tls13 ' */ + 1 /* length field*/) +
                      (context.size() + 1 /* length field*/));

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
   return m_expand->derive_key(
      length, secret, hkdf_label, std::vector<uint8_t>() /* just pleasing botan's interface */);
}

secure_vector<uint8_t> Cipher_State::derive_secret(const secure_vector<uint8_t>& secret,
                                                   std::string_view label,
                                                   const Transcript_Hash& messages_hash) const {
   return hkdf_expand_label(secret, label, messages_hash, m_hash->output_length());
}

std::vector<uint8_t> Cipher_State::empty_hash() const {
   m_hash->update("");
   return m_hash->final_stdvec();
}

void Cipher_State::update_read_keys(const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic || m_state == State::Completed);

   m_read_application_traffic_secret =
      hkdf_expand_label(m_read_application_traffic_secret, "traffic upd", {}, m_hash->output_length());

   const auto secret_label = fmt("{}_TRAFFIC_SECRET_{}",
                                 m_connection_side == Connection_Side::Server ? "CLIENT" : "SERVER",
                                 ++m_read_key_update_count);
   logger.maybe_log_secret(secret_label, m_read_application_traffic_secret);

   derive_read_traffic_key(m_read_application_traffic_secret);
}

void Cipher_State::update_write_keys(const Secret_Logger& logger) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic || m_state == State::Completed);
   m_write_application_traffic_secret =
      hkdf_expand_label(m_write_application_traffic_secret, "traffic upd", {}, m_hash->output_length());

   const auto secret_label = fmt("{}_TRAFFIC_SECRET_{}",
                                 m_connection_side == Connection_Side::Server ? "SERVER" : "CLIENT",
                                 ++m_write_key_update_count);
   logger.maybe_log_secret(secret_label, m_write_application_traffic_secret);

   derive_write_traffic_key(m_write_application_traffic_secret);
}

void Cipher_State::clear_read_keys() {
   zap(m_read_key);
   zap(m_read_iv);
   zap(m_read_application_traffic_secret);
}

void Cipher_State::clear_write_keys() {
   zap(m_write_key);
   zap(m_write_iv);
   zap(m_write_application_traffic_secret);
}

}  // namespace Botan::TLS
