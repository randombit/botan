/*
* TLS cipher state implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
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
 *                                     +-----> Derive-Secret(., "ext binder" | "res binder" | "imp binder", "")
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

#include <algorithm>
#include <limits>
#include <utility>

#include <botan/internal/tls_cipher_state.h>

#include <botan/aead.h>
#include <botan/assert.h>
#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_magic.h>

#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_impl_13.h>

namespace Botan::TLS {

std::unique_ptr<Cipher_State> Cipher_State::create(Connection_Side side, TLS_Flavor flavor, std::string_view prf_algo) {
   if(flavor == TLS_Flavor::DTLS) {
      throw Not_Implemented("DTLS 1.3 is not yet supported");
   } else {
      return std::make_unique<TLS_Cipher_State>(side, prf_algo);
   }
}

namespace {

std::unique_ptr<MessageAuthenticationCode> create_hmac(std::string_view hash) {
   return std::make_unique<HMAC>(HashFunction::create_or_throw(hash));
}

}  // namespace

Cipher_State::Cipher_State(Connection_Side whoami,
                           std::string_view hash_function,
                           ExpansionLabelPrefix expansion_label_prefix) :
      m_state(State::Uninitialized),
      m_connection_side(whoami),
      m_extract(std::make_unique<HKDF_Extract>(create_hmac(hash_function))),
      m_expand(std::make_unique<HKDF_Expand>(create_hmac(hash_function))),
      m_hash(HashFunction::create_or_throw(hash_function)),
      m_expansion_label_prefix(expansion_label_prefix),
      m_salt(m_hash->output_length(), 0x00),
      m_ticket_nonce(0) {}

Cipher_State::~Cipher_State() = default;

std::unique_ptr<Cipher_State> Cipher_State::init_with_server_hello(const Connection_Side side,
                                                                   TLS_Flavor flavor,
                                                                   secure_vector<uint8_t>&& shared_secret,
                                                                   const Ciphersuite& cipher,
                                                                   const Transcript_Hash& transcript_hash,
                                                                   SecretLoggerFn secret_logger) {
   auto cs = Cipher_State::create(side, flavor, cipher.prf_algo());
   cs->set_secret_logger(std::move(secret_logger));
   cs->advance_without_psk();
   cs->advance_with_server_hello(cipher, std::move(shared_secret), transcript_hash);
   return cs;
}

std::unique_ptr<Cipher_State> Cipher_State::init_with_psk(const Connection_Side side,
                                                          TLS_Flavor flavor,
                                                          const Cipher_State::PSK_Type type,
                                                          secure_vector<uint8_t>&& psk,
                                                          std::string_view prf_algo) {
   auto cs = Cipher_State::create(side, flavor, prf_algo);
   cs->advance_with_psk(type, std::move(psk));
   return cs;
}

void Cipher_State::advance_with_client_hello(const Transcript_Hash& transcript_hash) {
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
   maybe_log_secret("EARLY_EXPORTER_MASTER_SECRET", m_exporter_master_secret);

   m_salt = derive_secret(m_early_secret, "derived", empty_hash());
   zap(m_early_secret);

   m_state = State::EarlyTraffic;
}

void Cipher_State::advance_with_server_finished(const Transcript_Hash& transcript_hash) {
   BOTAN_ASSERT_NOMSG(m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NONNULL(m_hash);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   // We have to stash the client traffic application secret until the client's
   // Finished message is available. Only then can we update the respective
   // encryption/decryption epoch. See `advance_with_client_finished()`.
   m_client_application_traffic_secret_0 = derive_secret(master_secret, "c ap traffic", transcript_hash);
   auto server_application_traffic_secret = derive_secret(master_secret, "s ap traffic", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label "CLIENT_TRAFFIC_SECRET_0"
   //    and "SERVER_TRAFFIC_SECRET_0" to identify the secrets are using to
   //    protect the connection.
   maybe_log_secret("CLIENT_TRAFFIC_SECRET_0", m_client_application_traffic_secret_0);
   maybe_log_secret("SERVER_TRAFFIC_SECRET_0", server_application_traffic_secret);

   // Note: the secrets for processing client's application data
   //       are not derived before the client's Finished message
   //       was seen and the handshake can be considered finished.
   if(m_connection_side == Connection_Side::Server) {
      advance_write_epoch(server_application_traffic_secret);
   } else {
      advance_read_epoch(server_application_traffic_secret);
   }

   m_exporter_master_secret = derive_secret(master_secret, "exp master", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label "EXPORTER_SECRET" to
   //    identify the secret that is used in generating exporters(rfc8446
   //    Section 7.5).
   maybe_log_secret("EXPORTER_SECRET", m_exporter_master_secret);

   m_state = State::ServerApplicationTraffic;
}

void Cipher_State::advance_with_client_finished(const Transcript_Hash& transcript_hash) {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NONNULL(m_hash);
   BOTAN_ASSERT_NOMSG(!m_client_application_traffic_secret_0.empty());

   // With the client's Finished message, the handshake is complete and
   // we can process client application data.
   if(m_connection_side == Connection_Side::Server) {
      advance_read_epoch(m_client_application_traffic_secret_0);
   } else {
      advance_write_epoch(m_client_application_traffic_secret_0);
   }

   // The handshake is complete, we won't need the stashed client application
   // traffic secret any longer.
   zap(m_client_application_traffic_secret_0);

   const auto master_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));

   m_resumption_master_secret = derive_secret(master_secret, "res master", transcript_hash);

   // This was the final state change; the salt is no longer needed.
   zap(m_salt);

   m_state = State::Completed;
}

size_t Cipher_State::encrypt_output_length(const size_t input_length) const {
   // This assumes that the AEAD cipher's output length does not change
   // between epochs.
   return latest_write_epoch().cipher->output_length(input_length);
}

size_t Cipher_State::decrypt_output_length(const size_t input_length) const {
   // This assumes that the AEAD cipher's output length does not change
   // between epochs.
   return latest_read_epoch().cipher->output_length(input_length);
}

size_t Cipher_State::minimum_decryption_input_length() const {
   // This assumes that the AEAD cipher's minimal final size does not change
   // between epochs.
   return latest_read_epoch().cipher->minimum_final_size();
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

   return has_write_epoch();
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

   return has_read_epoch();
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

   BOTAN_ASSERT_NOMSG(has_write_epoch() == has_read_epoch());

   // Compare canonical AEAD names rather than substring-matching cipher_algo
   // against the AEAD's name(). starts_with() is both too permissive (an
   // AES-128/CCM-8 instance starts with "AES-128/CCM" so it would accept the
   // CCM-16 suite) and too restrictive (cipher_algo "AES-128/CCM(8)" does not
   // prefix the canonical "AES-128/CCM(8,3)"). Re-instantiating the AEAD from
   // cipher_algo yields the same canonical name() the suite would produce.
   if(has_write_epoch()) {
      auto canonical = AEAD_Mode::create(cipher.cipher_algo(), Cipher_Dir::Encryption);
      // This assumes that the AEAD cipher does not change between epochs.
      if(!canonical || canonical->name() != latest_write_epoch().cipher->name()) {
         return false;
      }
   }

   return true;
}

std::vector<uint8_t> Cipher_State::psk_binder_mac(
   const Transcript_Hash& transcript_hash_with_truncated_client_hello) const {
   BOTAN_ASSERT_NOMSG(m_state == State::PskBinder);
   BOTAN_ASSERT_NONNULL(m_hash);

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(m_binder_key);
   hmac.update(transcript_hash_with_truncated_client_hello);
   return hmac.final_stdvec();
}

std::vector<uint8_t> Cipher_State::finished_mac(const Transcript_Hash& transcript_hash) const {
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Server || m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Client || m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NONNULL(m_hash);

   const auto& epoch = latest_write_epoch();
   BOTAN_ASSERT_NOMSG(epoch.finished_key.has_value());

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(*epoch.finished_key);
   hmac.update(transcript_hash);
   return hmac.final_stdvec();
}

bool Cipher_State::verify_peer_finished_mac(const Transcript_Hash& transcript_hash,
                                            const std::vector<uint8_t>& peer_mac) const {
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Server || m_state == State::ServerApplicationTraffic);
   BOTAN_ASSERT_NOMSG(m_connection_side != Connection_Side::Client || m_state == State::HandshakeTraffic);
   BOTAN_ASSERT_NONNULL(m_hash);

   const auto& epoch = latest_read_epoch();
   BOTAN_ASSERT_NOMSG(epoch.finished_key.has_value());

   auto hmac = HMAC(m_hash->new_object());
   hmac.set_key(*epoch.finished_key);
   hmac.update(transcript_hash);
   return hmac.verify_mac(peer_mac);
}

secure_vector<uint8_t> Cipher_State::psk(const Ticket_Nonce& nonce) const {
   BOTAN_ASSERT_NOMSG(m_state == State::Completed);

   return derive_secret(m_resumption_master_secret, "resumption", nonce.get());
}

Ticket_Nonce Cipher_State::next_ticket_nonce() {
   BOTAN_STATE_CHECK(m_state == State::Completed);
   if(m_ticket_nonce_exhausted) {
      throw Botan::Invalid_State("ticket nonce pool exhausted");
   }

   auto retval = store_be<Ticket_Nonce>(m_ticket_nonce);

   if(m_ticket_nonce == std::numeric_limits<decltype(m_ticket_nonce)>::max()) {
      m_ticket_nonce_exhausted = true;
   } else {
      ++m_ticket_nonce;
   }

   return retval;
}

secure_vector<uint8_t> Cipher_State::export_key(std::string_view label, std::string_view context, size_t length) const {
   BOTAN_ASSERT_NOMSG(can_export_keys());
   BOTAN_ASSERT_NONNULL(m_hash);

   m_hash->update(context);
   const auto context_hash = m_hash->final_stdvec();
   return hkdf_expand_label(
      derive_secret(m_exporter_master_secret, label, empty_hash()), "exporter", context_hash, length);
}

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

std::array<uint8_t, NONCE_LENGTH> current_nonce(const uint64_t seq_no, std::span<const uint8_t> iv) {
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

size_t Cipher_State::protected_record_length(Epoch& epoch, size_t payload_length, size_t padding_bytes) {
   BOTAN_ASSERT_NONNULL(epoch.cipher);

   // RFC 8446 5.2
   //    type:  The TLSPlaintext.type value containing the content type of the record.
   constexpr size_t content_type_tag_length = 1;

   const size_t plaintext_length = payload_length + content_type_tag_length + padding_bytes;
   return epoch.cipher->output_length(plaintext_length);
}

MarshalledRecord Cipher_State::marshall_and_protect(Epoch& epoch,
                                                    std::span<const uint8_t> header,
                                                    std::span<const uint8_t> payload,
                                                    Record_Type type,
                                                    size_t padding_bytes) {
   BOTAN_ASSERT_NONNULL(epoch.cipher);

   const size_t record_length = header.size() + protected_record_length(epoch, payload.size(), padding_bytes);

   MarshalledRecord result;
   result.reserve(record_length);
   result.get().insert(result.end(), header.begin(), header.end());    // header
   result.get().insert(result.end(), payload.begin(), payload.end());  // content
   result.get().push_back(to_underlying(type));                        // type
   result.get().insert(result.end(), padding_bytes, 0x00);             // zeros

   epoch.cipher->set_associated_data(header);
   epoch.cipher->start(current_nonce(epoch.sequence_number, epoch.iv));
   epoch.cipher->finish(result, header.size() /* don't encrypt the header in the marshalled record */);
   BOTAN_DEBUG_ASSERT(result.size() == record_length);

   return result;
}

void Cipher_State::deprotect_and_hydrate_content_type(Epoch& epoch,
                                                      std::span<const uint8_t> header,
                                                      Record_Content& protected_record,
                                                      size_t incoming_record_size_limit) const {
   BOTAN_ASSERT_NOMSG(protected_record.sequence_number.has_value());
   BOTAN_ASSERT_NONNULL(epoch.cipher);
   BOTAN_ASSERT_NOMSG(protected_record.payload.size() <= MAX_CIPHERTEXT_SIZE_TLS13);

   epoch.cipher->set_associated_data(header);
   epoch.cipher->start(current_nonce(*protected_record.sequence_number, epoch.iv));
   epoch.cipher->finish(protected_record.payload);

   // RFC 8449 Section 4
   //    A TLS endpoint that receives a record larger than its advertised limit
   //    MUST generate a fatal "record_overflow" alert; a DTLS endpoint that
   //    receives a record larger than its advertised limit MAY either generate
   //    a fatal "record_overflow" alert or discard the record.
   //
   // We choose to generate a fatal alert for DTLS as well, given that this
   // error is detected after decryption only.
   if(protected_record.payload.size() > incoming_record_size_limit) {
      throw TLS_Exception(Alert::RecordOverflow, "Received an encrypted record that exceeds maximum plaintext size");
   }

   // Remove record padding (RFC 9846 5.4). The TLSInnerPlaintext layout is
   //   content || content_type || zero_padding
   //
   // This is intentionally not constant time. Checking it in constant time
   // requires scanning the entire record which significantly impacts receive
   // throughput, and in any case doing so seems pointless since the same
   // information (namely the length of the unpadded record) still leaks to the
   // same side channels later on during processing, when the application
   // actually receives and looks at the record.
   auto end_of_content = std::find_if(
      protected_record.payload.crbegin(), protected_record.payload.crend(), [](uint8_t b) { return b != 0x00; });

   // RFC 9846 5.4
   //   If a receiving implementation does not find a non-zero octet in the
   //   cleartext, it MUST terminate the connection with an
   //   "unexpected_message" alert.
   if(end_of_content == protected_record.payload.crend()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "No content type found in encrypted record");
   }

   // hydrate the actual content type from TLSInnerPlaintext
   protected_record.type = static_cast<Record_Type>(*end_of_content);

   // Truncate to drop the content_type byte and padding. resize() on a
   // vector of trivially-destructible elements is bookkeeping-only and
   // does not allocate or iterate over the dropped suffix.
   protected_record.payload.resize(protected_record.payload.size() -
                                   std::distance(protected_record.payload.crbegin(), end_of_content) -
                                   1 /* content type byte */);

   // RFC 9846 4.5.3
   //    Once a side has sent its Finished message and has received and
   //    validated the Finished message from its peer, it may begin to send and
   //    receive Application Data over the connection.
   //
   // See also:
   //  * https://github.com/randombit/botan/security/advisories/GHSA-pxcj-9ppx-g86g (CVE-2026-34582)
   if(protected_record.type == Record_Type::ApplicationData && !can_decrypt_application_traffic()) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Application data received before handshake completion");
   }

   // RFC 9846 5.4
   //    Implementations MUST NOT send Handshake and Alert records that have
   //    a zero-length TLSInnerPlaintext.content; if such a message is
   //    received, the receiving implementation MUST terminate the connection
   //    with an "unexpected_message" alert.
   if(protected_record.payload.empty() && protected_record.type != Record_Type::ApplicationData) {
      throw TLS_Exception(Alert::UnexpectedMessage, "Received a protected record with empty TLSInnerPlaintext content");
   }
}

void Cipher_State::advance_without_psk() {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);
   BOTAN_ASSERT_NONNULL(m_hash);

   // We are not using `m_early_secret` here because the secret won't be needed
   // in any further state advancement methods.
   const auto early_secret = hkdf_extract(secure_vector<uint8_t>(m_hash->output_length(), 0x00));
   m_salt = derive_secret(early_secret, "derived", empty_hash());

   // Without PSK we skip the `PskBinder` state and go right to `EarlyTraffic`.
   m_state = State::EarlyTraffic;
}

void Cipher_State::advance_with_psk(PSK_Type type, secure_vector<uint8_t>&& psk) {
   BOTAN_ASSERT_NOMSG(m_state == State::Uninitialized);
   BOTAN_ASSERT_NONNULL(m_hash);

   m_early_secret = hkdf_extract(std::move(psk));

   // RFC 8446 and RFC 9258 specify these strings
   const char* binder_label = [type]() -> const char* {
      switch(type) {
         case PSK_Type::Resumption:
            return "res binder";
         case PSK_Type::External:
            return "ext binder";
         case PSK_Type::Imported:
            return "imp binder";
      }
      BOTAN_ASSERT_UNREACHABLE();
   }();

   // RFC 8446 4.2.11.2
   //    The PskBinderEntry is computed in the same way as the Finished message
   //    [...] but with the BaseKey being the binder_key derived via the key
   //    schedule from the corresponding PSK which is being offered.
   //
   // Hence we are doing the binder key derivation and expansion in one go.
   const auto binder_key = derive_secret(m_early_secret, binder_label, empty_hash());
   m_binder_key = hkdf_expand_label(binder_key, "finished", {}, m_hash->output_length());

   // TODO: Implement early data (0-RTT) and derive early traffic secrets here.

   m_state = State::PskBinder;
}

void Cipher_State::advance_with_server_hello(const Ciphersuite& cipher,
                                             secure_vector<uint8_t>&& shared_secret,
                                             const Transcript_Hash& transcript_hash) {
   BOTAN_ASSERT_NOMSG(m_state == State::EarlyTraffic);
   BOTAN_STATE_CHECK(is_compatible_with(cipher));
   BOTAN_STATE_CHECK(!m_ciphersuite.has_value());

   m_ciphersuite = cipher;

   const auto handshake_secret = hkdf_extract(std::move(shared_secret));

   const auto client_handshake_traffic_secret = derive_secret(handshake_secret, "c hs traffic", transcript_hash);
   const auto server_handshake_traffic_secret = derive_secret(handshake_secret, "s hs traffic", transcript_hash);

   // draft-thomson-tls-keylogfile-00 Section 3.1
   //    An implementation of TLS 1.3 use the label
   //    "CLIENT_HANDSHAKE_TRAFFIC_SECRET" and "SERVER_HANDSHAKE_TRAFFIC_SECRET"
   //    to identify the secrets are using to protect handshake messages.
   maybe_log_secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_handshake_traffic_secret);
   maybe_log_secret("SERVER_HANDSHAKE_TRAFFIC_SECRET", server_handshake_traffic_secret);

   if(m_connection_side == Connection_Side::Server) {
      advance_read_epoch(client_handshake_traffic_secret, true /* handshake epoch */);
      advance_write_epoch(server_handshake_traffic_secret, true /* handshake epoch */);
   } else {
      advance_read_epoch(server_handshake_traffic_secret, true /* handshake epoch */);
      advance_write_epoch(client_handshake_traffic_secret, true /* handshake epoch */);
   }

   m_salt = derive_secret(handshake_secret, "derived", empty_hash());

   m_state = State::HandshakeTraffic;
}

Cipher_State::Epoch Cipher_State::create_epoch(Cipher_Dir direction,
                                               const secure_vector<uint8_t>& traffic_secret,
                                               bool handshake_epoch) const {
   BOTAN_ASSERT_NONNULL(m_hash);
   BOTAN_ASSERT_NOMSG(m_ciphersuite.has_value());

   return {
      .cipher = [&]() -> std::unique_ptr<AEAD_Mode> {
         auto cipher = AEAD_Mode::create_or_throw(m_ciphersuite->cipher_algo(), direction);
         cipher->set_key(hkdf_expand_label(traffic_secret, "key", {}, cipher->minimum_keylength()));
         return cipher;
      }(),
      .iv = hkdf_expand_label(traffic_secret, "iv", {}, NONCE_LENGTH),
      .sequence_number = 0,
      .traffic_secret = traffic_secret,
      .finished_key = [&]() -> std::optional<secure_vector<uint8_t>> {
         if(handshake_epoch) {
            // Key derivation for the MAC in the "Finished" handshake message
            // as described in RFC 8446 4.4.4
            return hkdf_expand_label(traffic_secret, "finished", {}, m_hash->output_length());
         }
         return {};
      }(),
   };
}

const Ciphersuite& Cipher_State::ciphersuite() const {
   BOTAN_ASSERT_NOMSG(m_ciphersuite.has_value());
   return *m_ciphersuite;
}

secure_vector<uint8_t> Cipher_State::hkdf_extract(std::span<const uint8_t> ikm) const {
   BOTAN_ASSERT_NONNULL(m_extract);
   BOTAN_ASSERT_NONNULL(m_hash);
   return m_extract->derive_key(m_hash->output_length(), ikm, m_salt, std::vector<uint8_t>());
}

secure_vector<uint8_t> Cipher_State::hkdf_expand_label(const secure_vector<uint8_t>& secret,
                                                       std::string_view label,
                                                       const std::vector<uint8_t>& context,
                                                       const size_t length) const {
   BOTAN_ASSERT_NONNULL(m_expand);
   BOTAN_ARG_CHECK(length <= std::numeric_limits<uint16_t>::max(), "invalid length");
   BOTAN_ARG_CHECK(context.size() <= 255, "context too large");

   const auto hkdf_label =
      concat<secure_vector<uint8_t>>(store_be(static_cast<uint16_t>(length)),
                                     store_be(static_cast<uint8_t>(m_expansion_label_prefix.size() + label.size())),
                                     m_expansion_label_prefix,
                                     as_span_of_bytes(label),
                                     store_be(static_cast<uint8_t>(context.size())),
                                     context);

   // HKDF-Expand
   return m_expand->derive_key(
      length, secret, hkdf_label, std::vector<uint8_t>() /* just pleasing botan's interface */);
}

secure_vector<uint8_t> Cipher_State::derive_secret(const secure_vector<uint8_t>& secret,
                                                   std::string_view label,
                                                   const Transcript_Hash& messages_hash) const {
   BOTAN_ASSERT_NONNULL(m_hash);
   return hkdf_expand_label(secret, label, messages_hash, m_hash->output_length());
}

std::vector<uint8_t> Cipher_State::empty_hash() const {
   BOTAN_ASSERT_NONNULL(m_hash);
   m_hash->update("");
   return m_hash->final_stdvec();
}

void Cipher_State::update_read_keys() {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic || m_state == State::Completed);
   BOTAN_ASSERT_NONNULL(m_hash);

   auto& epoch = latest_read_epoch();

   const auto new_read_application_traffic_secret =
      hkdf_expand_label(epoch.traffic_secret, "traffic upd", {}, m_hash->output_length());

   const auto secret_label = fmt("{}_TRAFFIC_SECRET_{}",
                                 m_connection_side == Connection_Side::Server ? "CLIENT" : "SERVER",
                                 ++m_read_key_update_count);
   maybe_log_secret(secret_label, new_read_application_traffic_secret);

   advance_read_epoch(new_read_application_traffic_secret);
}

void Cipher_State::update_write_keys() {
   BOTAN_ASSERT_NOMSG(m_state == State::ServerApplicationTraffic || m_state == State::Completed);
   BOTAN_ASSERT_NONNULL(m_hash);

   auto& epoch = latest_write_epoch();

   const auto new_write_application_traffic_secret =
      hkdf_expand_label(epoch.traffic_secret, "traffic upd", {}, m_hash->output_length());

   const auto secret_label = fmt("{}_TRAFFIC_SECRET_{}",
                                 m_connection_side == Connection_Side::Server ? "SERVER" : "CLIENT",
                                 ++m_write_key_update_count);
   maybe_log_secret(secret_label, new_write_application_traffic_secret);

   advance_write_epoch(new_write_application_traffic_secret);
}

uint64_t Cipher_State::records_encrypted_with_current_key() const {
   return latest_write_epoch().sequence_number;
}

uint64_t Cipher_State::records_decrypted_with_current_key() const {
   return latest_read_epoch().sequence_number;
}

TLS_Cipher_State::TLS_Cipher_State(Connection_Side side, std::string_view prf_algo) :
      Cipher_State(side, prf_algo, {'t', 'l', 's', '1', '3', ' '} /* RFC 9846 7.1 */) {}

TLS_Cipher_State::~TLS_Cipher_State() = default;

MarshalledRecord TLS_Cipher_State::protect_record(Record_Type type,
                                                  std::span<const uint8_t> plaintext,
                                                  size_t padding_bytes) {
   BOTAN_ASSERT_NOMSG(m_write_epoch.has_value());
   BOTAN_STATE_CHECK_MSG(type != Record_Type::ApplicationData || can_encrypt_application_traffic(),
                         "Application data must not be encrypted before handshake completion");

   // RFC 8446 5.3
   //    Sequence numbers MUST NOT wrap.
   if(m_write_epoch->sequence_number == std::numeric_limits<uint64_t>::max()) {
      throw Invalid_State("TLS write sequence number overflow");
   }

   // RFC 9846 5.2
   //    opaque_type: The outer opaque_type field of a TLSCiphertext record is
   //                 always set to the value 23 (application_data) [...]
   //    legacy_record_version: [...] is always 0x0303. TLS 1.3 TLSCiphertexts
   //                           are not generated until after TLS 1.3 has been
   //                           negotiated, so there are no historical
   //                           compatibility concerns [...].
   //    length: [...] of the following TLSCiphertext.encrypted_record, which is
   //            the sum of the lengths of the content and the padding, plus one
   //            for the inner content type, plus any expansion added by the
   //            AEAD algorithm.
   const auto header = Record_TLS::serialize_header(
      Record_Type::ApplicationData,
      Protocol_Version::TLS_V12 /* = 0x0303 */,
      checked_cast_to<uint16_t>(protected_record_length(*m_write_epoch, plaintext.size(), padding_bytes)));

   auto result = marshall_and_protect(*m_write_epoch, header, plaintext, type, padding_bytes);
   ++m_write_epoch->sequence_number;
   return result;
}

Record TLS_Cipher_State::deprotect_record(Record_TLS record, size_t incoming_record_size_limit) {
   BOTAN_ASSERT_NOMSG(m_read_epoch.has_value());
   BOTAN_ARG_CHECK(record.type() == Record_Type::ApplicationData, "Record type must be ApplicationData");

   // RFC 9846 5.2
   //    length: The length (in bytes) [...], which is the sum of the lengths of
   //            the content and the padding, plus one for the inner content
   //            type, plus any expansion added by the AEAD algorithm.
   //    [...]
   //    If the decryption fails, the receiver MUST terminate the connection
   //    with a "bad_record_mac" alert.
   //
   // If the protected record contains less bytes than the expected AEAD tag we
   // can already fail early because the decryption will fail anyway.
   if(record.payload().size() < m_read_epoch->cipher->minimum_final_size()) {
      throw TLS_Exception(Alert::BadRecordMac, "incomplete record mac received");
   }

   // RFC 9846 6.2
   //    record_overflow: A TLSCiphertext record was received that had a length
   //    more than 2^14 + 256 bytes, or a record decrypted to a TLSPlaintext
   //    record with more than 214 bytes (or some other negotiated limit).
   //
   // RFC 8449 4.
   //    A TLS endpoint that receives a record larger than its advertised limit
   //    MUST generate a fatal "record_overflow" alert [...].
   if(decrypt_output_length(record.payload().size()) > incoming_record_size_limit) {
      throw TLS_Exception(Alert::RecordOverflow, "Received an encrypted record that exceeds maximum plaintext size");
   }

   // RFC 8446 5.3
   //    Sequence numbers MUST NOT wrap.
   if(m_read_epoch->sequence_number == std::numeric_limits<uint64_t>::max()) {
      throw Invalid_State("TLS read sequence number overflow");
   }

   auto result = Record_Content{
      .type = Record_Type::Invalid,
      .sequence_number = m_read_epoch->sequence_number++,
      .payload = record.take_payload(),
   };

   deprotect_and_hydrate_content_type(*m_read_epoch, record.header(), result, incoming_record_size_limit);

   // RFC 9846 5.
   //    An implementation [...] which receives a protected change_cipher_spec
   //    record MUST abort the handshake with an "unexpected_message" alert.
   //    [....]
   //    If a TLS implementation receives an unexpected record type, it MUST
   //    terminate the connection with an "unexpected_message" alert.
   //
   // RFC 9846 5.1
   //    enum {
   //        invalid(0),
   //        change_cipher_spec(20),
   //        alert(21),
   //        handshake(22),
   //        application_data(23),
   //        (255)
   //    } ContentType;
   if(result.type != Record_Type::ApplicationData &&  //
      result.type != Record_Type::Handshake &&        //
      result.type != Record_Type::Alert) {
      throw TLS_Exception(Alert::UnexpectedMessage, "protected TLS record type had unexpected value");
   }

   return annotate_record_type(std::move(result));
}

void TLS_Cipher_State::advance_write_epoch(const secure_vector<uint8_t>& traffic_secret, bool handshake_epoch) {
   m_write_epoch = create_epoch(Cipher_Dir::Encryption, traffic_secret, handshake_epoch);
}

void TLS_Cipher_State::advance_read_epoch(const secure_vector<uint8_t>& traffic_secret, bool handshake_epoch) {
   m_read_epoch = create_epoch(Cipher_Dir::Decryption, traffic_secret, handshake_epoch);
}

void TLS_Cipher_State::clear_write_keys() {
   m_write_epoch.reset();
}

void TLS_Cipher_State::clear_read_keys() {
   m_read_epoch.reset();
}

}  // namespace Botan::TLS
