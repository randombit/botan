/*
* TLS Channels
* (C) 2011,2012,2014,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_12.h>

#include <botan/kdf.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_messages_12.h>
#include <botan/tls_policy.h>
#include <botan/x509cert.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <utility>

namespace Botan::TLS {

namespace {

bool is_new_dtls_association_client_hello(std::span<const uint8_t> msg_and_header, Record_Type record_type) {
   constexpr size_t DTLS_HANDSHAKE_HEADER_SIZE = 12;

   // Every new DTLS handshake starts at message_seq 0. A cookie-bearing
   // ClientHello uses message_seq 1, so one arriving late belongs to the
   // previous handshake and must not replace the active association's state.
   return record_type == Record_Type::Handshake && msg_and_header.size() >= DTLS_HANDSHAKE_HEADER_SIZE &&
          static_cast<Handshake_Type>(msg_and_header[0]) == Handshake_Type::ClientHello &&
          load_be(msg_and_header.subspan<4, 2>()) == 0;
}

// Cap on the number of non-zero-epoch cipher states retained per direction.
// The current epoch is in active use; one earlier epoch covers any in-flight
// DTLS records sent immediately before a rekey. Epoch 0 is the pre-handshake
// plaintext placeholder and is always retained.
//
// Note the logic in prune_epochs in tls_seq_numbers.h assumes this is exactly 2
// so adjust that code if changing this.
constexpr size_t TLS_RETAINED_CIPHERSTATES = 2;

// The "default MSL specified for TCP" of RFC 6347 4.1; RFC 793 sets it to two
// minutes. Bounds how long a retired DTLS read epoch stays usable.
constexpr uint64_t TCP_MSL_MS = 2 * 60 * 1000;

template <typename T>
void prune_old_cipher_states(std::map<uint16_t, T>& states) {
   // std::map iterates in ascending key order. Drop the lowest non-zero
   // entries until at most TLS_RETAINED_CIPHERSTATES remain. The newly
   // installed epoch is the highest key, so it is preserved.
   size_t non_zero = states.size() - states.count(0);
   auto it = states.lower_bound(1);
   while(non_zero > TLS_RETAINED_CIPHERSTATES) {
      it = states.erase(it);
      --non_zero;
   }
}

// Run fn, absorbing the exceptions that report malformed input when `absorb`
// is set. Used where the input is unauthenticated epoch-zero data that must
// not be able to tear down an established association. Only TLS_Exception and
// Decoding_Error are absorbed: an Internal_Error from one of the reassembly
// accounting assertions, or a failed allocation, still propagates rather than
// leaving the association running on state those assertions exist to protect.
template <typename F>
void absorb_malformed_input_errors(bool absorb, F fn) {
   try {
      fn();
   } catch(const TLS_Exception&) {
      if(!absorb) {
         throw;
      }
   } catch(const Decoding_Error&) {
      if(!absorb) {
         throw;
      }
   }
}

}  // namespace

Channel_Impl_12::Channel_Impl_12(const std::shared_ptr<Callbacks>& callbacks,
                                 const std::shared_ptr<Session_Manager>& session_manager,
                                 const std::shared_ptr<RandomNumberGenerator>& rng,
                                 const std::shared_ptr<const Policy>& policy,
                                 bool is_server,
                                 bool is_datagram,
                                 size_t reserved_io_buffer_size) :
      m_is_server(is_server),
      m_is_datagram(is_datagram),
      m_callbacks(callbacks),
      m_session_manager(session_manager),
      m_policy(policy),
      m_rng(rng),
      m_has_been_closed(false) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_session_manager);
   BOTAN_ASSERT_NONNULL(m_rng);
   BOTAN_ASSERT_NONNULL(m_policy);

   /* epoch 0 is plaintext, thus null cipher state */
   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = {};

   m_writebuf.reserve(reserved_io_buffer_size);
   m_readbuf.reserve(reserved_io_buffer_size);
}

void Channel_Impl_12::reset_state() {
   m_active_state.reset();
   m_pending_state.reset();
   m_epochs_before_latest_renegotiation.reset();
   m_resumption_handle.reset();
   m_readbuf.clear();
   m_write_cipher_states.clear();
   m_read_cipher_states.clear();
}

void Channel_Impl_12::note_resumption_handle(std::optional<Session_Handle> handle) {
   m_resumption_handle = std::move(handle);
}

std::vector<Session_Handle> Channel_Impl_12::take_sessions_to_invalidate() {
   // A ticket-backed session is not cached under the ServerHello session ID, so
   // both handles have to be collected.
   std::vector<Session_Handle> handles;

   if(m_resumption_handle.has_value()) {
      handles.push_back(m_resumption_handle.value());
      m_resumption_handle.reset();
   }

   if(m_active_state.has_value()) {
      const auto& sid = m_active_state->session_id();
      if(!sid.empty()) {
         handles.emplace_back(sid);
      }
   }

   return handles;
}

void Channel_Impl_12::invalidate_sessions(const std::vector<Session_Handle>& handles) {
   // RFC 5246 7.2.2: "Servers and clients MUST forget any session-identifiers,
   // keys, and secrets associated with a failed connection.  Thus, any
   // connection terminated with a fatal alert MUST NOT be resumed."
   //
   // Best effort, and deliberately last: remove() reaches application-supplied
   // storage and can throw, and by then the keys are already gone. Letting a
   // failed cache eviction abort the teardown would leave the channel usable
   // after a security-fatal event, which is the worse of the two outcomes. A
   // stateless ticket issuer has nothing to remove and cannot revoke what it
   // already handed out.
   for(const auto& handle : handles) {
      try {
         session_manager().remove(handle);
      } catch(...) {}
   }
}

void Channel_Impl_12::reset_active_association_state() {
   // This operation only makes sense for DTLS
   BOTAN_ASSERT_NOMSG(m_is_datagram);
   m_active_state.reset();
   m_read_cipher_states.clear();
   m_write_cipher_states.clear();

   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = {};

   if(m_sequence_numbers) {
      m_sequence_numbers->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
   }
}

Channel_Impl_12::~Channel_Impl_12() = default;

Connection_Sequence_Numbers& Channel_Impl_12::sequence_numbers() const {
   BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
   return *m_sequence_numbers;
}

std::shared_ptr<Connection_Cipher_State> Channel_Impl_12::read_cipher_state_epoch(uint16_t epoch) const {
   auto i = m_read_cipher_states.find(epoch);
   if(i == m_read_cipher_states.end()) {
      throw Internal_Error("TLS::Channel_Impl_12 No read cipherstate for epoch " + std::to_string(epoch));
   }

   // RFC 6347 4.1: "In general, implementations SHOULD discard packets from
   // earlier epochs, but if packet loss causes noticeable problems they MAY
   // choose to retain keying material from previous epochs for up to the
   // default MSL specified for TCP [TCP] to allow for packet reordering."
   // read_dtls_record drops the record when this throws.
   if(const auto& retired_at = i->second.retired_at; retired_at.has_value()) {
      const auto now = callbacks().tls_current_monotonic_clock_ms();
      const auto retired = retired_at.value();
      BOTAN_ASSERT_NOMSG(now >= retired);
      if(now - retired > TCP_MSL_MS) {
         throw Invalid_State("TLS::Channel_Impl_12 Read cipherstate for epoch " + std::to_string(epoch) +
                             " is past its retention window");
      }
   }

   return i->second.state;
}

std::shared_ptr<Connection_Cipher_State> Channel_Impl_12::write_cipher_state_epoch(uint16_t epoch) const {
   auto i = m_write_cipher_states.find(epoch);
   if(i == m_write_cipher_states.end()) {
      throw Internal_Error("TLS::Channel_Impl_12 No write cipherstate for epoch " + std::to_string(epoch));
   }
   return i->second;
}

std::vector<X509_Certificate> Channel_Impl_12::peer_cert_chain() const {
   if(m_active_state.has_value()) {
      return m_active_state->peer_certs();
   }
   return std::vector<X509_Certificate>();
}

std::optional<std::string> Channel_Impl_12::external_psk_identity() const {
   if(m_active_state.has_value()) {
      return m_active_state->psk_identity();
   }
   if(const auto* state = pending_state()) {
      return state->psk_identity();
   }
   return std::nullopt;
}

Handshake_State& Channel_Impl_12::create_handshake_state(Protocol_Version version) {
   if(pending_state() != nullptr) {
      throw Internal_Error("create_handshake_state called during handshake");
   }

   if(m_active_state.has_value()) {
      const Protocol_Version active_version = m_active_state->version();

      if(active_version.is_datagram_protocol() != version.is_datagram_protocol()) {
         throw TLS_Exception(Alert::ProtocolVersion,
                             "Active state using version " + active_version.to_string() + " cannot change to " +
                                version.to_string() + " in pending");
      }
   }

   if(!m_sequence_numbers) {
      if(version.is_datagram_protocol()) {
         m_sequence_numbers = std::make_unique<Datagram_Sequence_Numbers>();
      } else {
         m_sequence_numbers = std::make_unique<Stream_Sequence_Numbers>();
      }
   }

   m_epochs_before_latest_renegotiation = Epochs_Before_Latest_Renegotiation{sequence_numbers().current_read_epoch(),
                                                                             sequence_numbers().current_write_epoch()};

   using namespace std::placeholders;

   std::unique_ptr<Handshake_IO> io;
   if(version.is_datagram_protocol()) {
      const uint16_t mtu = static_cast<uint16_t>(policy().dtls_default_mtu());
      const size_t initial_timeout_ms = policy().dtls_initial_timeout();
      const size_t max_timeout_ms = policy().dtls_maximum_timeout();
      const std::optional<size_t> max_retransmissions = policy().dtls_maximum_retransmissions();

      auto send_record_f = [this](uint16_t epoch, Record_Type record_type, const std::vector<uint8_t>& record) {
         send_record_under_epoch(epoch, record_type, record);
      };
      auto clock_f = [this]() { return callbacks().tls_current_monotonic_clock_ms(); };
      io = std::make_unique<Datagram_Handshake_IO>(send_record_f,
                                                   clock_f,
                                                   sequence_numbers(),
                                                   mtu,
                                                   initial_timeout_ms,
                                                   max_timeout_ms,
                                                   max_retransmissions,
                                                   policy().maximum_handshake_message_size());
   } else {
      auto send_record_f = [this](Record_Type rec_type, const std::vector<uint8_t>& record) {
         send_record(rec_type, record);
      };
      io = std::make_unique<Stream_Handshake_IO>(send_record_f);
   }

   m_pending_state = new_handshake_state(std::move(io));

   if(m_active_state.has_value()) {
      m_pending_state->set_version(m_active_state->version());
   }

   return *m_pending_state;
}

bool Channel_Impl_12::pending_handshake_epochs_unmoved() const {
   // Nothing pending: there is nothing to act on, and the epoch markers are
   // unset, so the comparison would be meaningless.
   if(!m_pending_state || !m_epochs_before_latest_renegotiation.has_value()) {
      return true;
   }

   // Before either ChangeCipherSpec the established association still owns both
   // epochs, so dropping the pending handshake leaves it exactly as it was.
   return sequence_numbers().current_read_epoch() == m_epochs_before_latest_renegotiation->read_epoch &&
          sequence_numbers().current_write_epoch() == m_epochs_before_latest_renegotiation->write_epoch;
}

void Channel_Impl_12::clear_pending_handshake_state() {
   m_pending_state.reset();
   m_epochs_before_latest_renegotiation.reset();
}

/*
* The retransmission budget is exhausted and this handshake will not complete.
* Leaving the pending state installed makes every later timeout_check throw
* again from unchanged state, and blocks renegotiate(), so the channel can
* neither recover nor be retried.
*/
void Channel_Impl_12::abandon_timed_out_handshake() {
   if(m_active_state.has_value() && pending_handshake_epochs_unmoved()) {
      // A renegotiation that never reached its ChangeCipherSpec. The
      // established association is untouched, so keep it and let the
      // application try again.
      clear_pending_handshake_state();
   } else {
      // Either there is no established association to fall back to, or a
      // ChangeCipherSpec has already moved an epoch and there is no rollback
      // that would leave keys, identity and sequence numbers describing the
      // same handshake. Close.
      m_has_been_closed = true;
      reset_state();
   }
}

bool Channel_Impl_12::timeout_check() {
   if(m_is_datagram && !m_has_been_closed && m_pending_state) {
      try {
         return m_pending_state->handshake_io().timeout_check();
      } catch(const TLS_Exception&) {
         abandon_timed_out_handshake();
         throw;
      }
   }

   // Old cipher states are pruned at install time (see prune_old_cipher_states),
   // so no periodic cleanup is needed here.
   return false;
}

void Channel_Impl_12::renegotiate(bool force_full_renegotiation) {
   if(pending_state() != nullptr) {  // currently in handshake?
      return;
   }

   if(m_active_state.has_value()) {
      // A DTLS handshake consumes one read and one write epoch. Refuse here if
      // either is spent, so the caller learns before the handshake tears the
      // working association down partway through. See next_epoch().
      if(m_is_datagram &&
         (sequence_numbers().current_read_epoch() == 0xFFFF || sequence_numbers().current_write_epoch() == 0xFFFF)) {
         throw Invalid_State("DTLS epoch counter exhausted, a new association is required");
      }

      if(!force_full_renegotiation) {
         force_full_renegotiation = !policy().allow_resumption_for_renegotiation();
      }

      initiate_handshake(create_handshake_state(m_active_state->version()), force_full_renegotiation);
   } else {
      throw Invalid_State("Cannot renegotiate on inactive connection");
   }
}

void Channel_Impl_12::update_traffic_keys(bool /*update_requested*/) {
   throw Invalid_Argument("cannot update traffic keys on a TLS 1.2 channel");
}

void Channel_Impl_12::change_cipher_spec_reader(Connection_Side side) {
   const auto* pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(), "Have received server hello");

   if(pending->server_hello()->compression_method() != 0) {
      throw Internal_Error("Negotiated unknown compression algorithm");
   }

   sequence_numbers().new_read_cipher_state();

   const uint16_t epoch = sequence_numbers().current_read_epoch();

   BOTAN_ASSERT(!m_read_cipher_states.contains(epoch), "No read cipher state currently set for next epoch");

   // flip side as we are reading
   auto read_state = std::make_shared<Connection_Cipher_State>(
      pending->version(),
      (side == Connection_Side::Client) ? Connection_Side::Server : Connection_Side::Client,
      false,
      pending->ciphersuite(),
      pending->session_keys(),
      pending->server_hello()->supports_encrypt_then_mac());

   // The epoch we just left is retained only to absorb reordering, so start its
   // clock now (see read_cipher_state_epoch). Epoch 0 is the plaintext
   // placeholder and holds no keys, so the window does not apply to it.
   if(m_is_datagram && epoch > 1) {
      if(auto prev = m_read_cipher_states.find(static_cast<uint16_t>(epoch - 1)); prev != m_read_cipher_states.end()) {
         prev->second.retired_at = callbacks().tls_current_monotonic_clock_ms();
      }
   }

   m_read_cipher_states[epoch] = Retained_Read_Cipher_State{.state = read_state, .retired_at = std::nullopt};
   prune_old_cipher_states(m_read_cipher_states);
}

void Channel_Impl_12::change_cipher_spec_writer(Connection_Side side) {
   const auto* pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(), "Have received server hello");

   if(pending->server_hello()->compression_method() != 0) {
      throw Internal_Error("Negotiated unknown compression algorithm");
   }

   sequence_numbers().new_write_cipher_state();

   const uint16_t epoch = sequence_numbers().current_write_epoch();

   BOTAN_ASSERT(!m_write_cipher_states.contains(epoch), "No write cipher state currently set for next epoch");

   auto write_state = std::make_shared<Connection_Cipher_State>(pending->version(),
                                                                side,
                                                                true,
                                                                pending->ciphersuite(),
                                                                pending->session_keys(),
                                                                pending->server_hello()->supports_encrypt_then_mac());

   m_write_cipher_states[epoch] = write_state;
   prune_old_cipher_states(m_write_cipher_states);
}

bool Channel_Impl_12::is_handshake_complete() const {
   return m_active_state.has_value();
}

bool Channel_Impl_12::is_active() const {
   return !is_closed() && is_handshake_complete();
}

std::optional<std::chrono::milliseconds> Channel_Impl_12::next_retransmission_timeout() const {
   if(m_is_datagram && !m_has_been_closed && m_pending_state) {
      return m_pending_state->handshake_io().next_retransmission_timeout();
   }

   return std::nullopt;
}

bool Channel_Impl_12::is_closed() const {
   return m_has_been_closed;
}

void Channel_Impl_12::activate_session() {
   BOTAN_ASSERT_NONNULL(m_pending_state);

   const auto& state = *m_pending_state;

   if(!state.version().is_datagram_protocol()) {
      // TLS is easy just remove all but the current state
      const uint16_t current_epoch = sequence_numbers().current_write_epoch();

      const auto not_current_epoch = [current_epoch](uint16_t epoch) { return (epoch != current_epoch); };

      map_remove_if(not_current_epoch, m_write_cipher_states);
      map_remove_if(not_current_epoch, m_read_cipher_states);
   }

   // In a full handshake the server sends the terminal flight; in an
   // abbreviated handshake the client does. Both endpoints retain handshake
   // sequence state, but only the terminal sender replays its outgoing flight.
   const bool sent_terminal_dtls_flight = m_is_datagram && (m_is_server == (state.server_hello_done() != nullptr));

   if(m_is_datagram) {
      m_active_state = Active_Connection_State_12(state, application_protocol(), m_pending_state->take_handshake_io());
      if(auto* dtls_io = m_active_state->dtls_handshake_io()) {
         // Retain receive sequence state on both endpoints to distinguish a
         // retransmission from an unexpected new handshake message. Only the
         // terminal-flight sender responds by replaying its final flight.
         dtls_io->finalize_handshake(sent_terminal_dtls_flight);
      }
   } else {
      m_active_state = Active_Connection_State_12(state, application_protocol());
   }

   clear_pending_handshake_state();

   callbacks().tls_session_activated();
}

size_t Channel_Impl_12::from_peer(std::span<const uint8_t> data) {
   const bool allow_epoch0_restart = m_is_datagram && m_is_server && policy().allow_dtls_epoch0_restart();

   const auto* input = data.data();
   auto input_size = data.size();

   try {
      while(input_size > 0) {
         // A fatal alert destroys the cipher states, so nothing further can even
         // be decrypted. Closure by close_notify is different: the responding
         // close_notify still has to be read, so those records keep flowing
         // through the loop and are filtered per record type below.
         if(m_had_fatal_alert) {
            return 0;
         }

         size_t consumed = 0;

         auto get_epoch = [this](uint16_t epoch) { return read_cipher_state_epoch(epoch); };

         const Record_Header record = read_record(m_is_datagram,
                                                  m_readbuf,
                                                  input,
                                                  input_size,
                                                  consumed,
                                                  m_record_buf,
                                                  m_sequence_numbers.get(),
                                                  get_epoch,
                                                  allow_epoch0_restart);

         const size_t needed = record.needed();

         BOTAN_ASSERT(consumed > 0, "Got to eat something");

         BOTAN_ASSERT(consumed <= input_size, "Record reader consumed sane amount");

         input += consumed;
         input_size -= consumed;

         BOTAN_ASSERT(input_size == 0 || needed == 0, "Got a full record or consumed all input");

         if(input_size == 0 && needed != 0) {
            return needed;  // need more data to complete record
         }

         // Ignore invalid records in DTLS
         if(m_is_datagram && record.type() == Record_Type::Invalid) {
            return 0;
         }

         const bool old_unprotected_record = m_is_datagram && record.epoch() == 0 && m_active_state.has_value() &&
                                             sequence_numbers().current_read_epoch() > 0;

         // Once encrypted traffic is expected, epoch-zero records are
         // unauthenticated. Only handshake records can be useful as part of a
         // retransmitted flight or an explicitly allowed association restart.
         if(old_unprotected_record && record.type() != Record_Type::Handshake &&
            record.type() != Record_Type::ChangeCipherSpec) {
            continue;
         }

         if(m_record_buf.size() > MAX_PLAINTEXT_SIZE) {
            if(old_unprotected_record) {
               continue;
            }

            throw TLS_Exception(Alert::RecordOverflow, "TLS plaintext record is larger than allowed maximum");
         }

         const bool epoch0_restart = allow_epoch0_restart && record.epoch() == 0 && m_active_state.has_value();
         BOTAN_ASSERT_IMPLICATION(epoch0_restart, allow_epoch0_restart, "Allowed state");

         const bool initial_record = epoch0_restart || (pending_state() == nullptr && !m_active_state.has_value());
         bool initial_handshake_message = false;
         if(record.type() == Record_Type::Handshake && !m_record_buf.empty()) {
            const Handshake_Type type = static_cast<Handshake_Type>(m_record_buf[0]);
            initial_handshake_message = (type == Handshake_Type::ClientHello);
         }

         if(record.type() != Record_Type::Alert && !old_unprotected_record) {
            if(initial_record) {
               // For initial records just check for basic sanity
               if(record.version().major_version() != 3 && record.version().major_version() != 0xFE) {
                  throw TLS_Exception(Alert::ProtocolVersion, "Received unexpected record version in initial record");
               }
            } else if(const auto* pending = pending_state()) {
               if(pending->server_hello() != nullptr && !initial_handshake_message &&
                  record.version() != pending->version()) {
                  throw TLS_Exception(Alert::ProtocolVersion, "Received unexpected record version");
               }
            } else if(m_active_state.has_value()) {
               if(record.version() != m_active_state->version() && !initial_handshake_message) {
                  throw TLS_Exception(Alert::ProtocolVersion, "Received unexpected record version");
               }
            }
         }

         // RFC 5246 7.2.1: "Any data received after a closure alert is ignored."
         // This is about a closure alert the peer sent us. A peer that keeps
         // talking after *our* close_notify is a different case, kept as an
         // error below; BoGo's Shutdown-Shim-ApplicationData requires it.
         if(m_peer_closed_connection && record.type() != Record_Type::Alert) {
            continue;
         }

         if(record.type() == Record_Type::Handshake || record.type() == Record_Type::ChangeCipherSpec) {
            if(m_has_been_closed) {
               throw TLS_Exception(Alert::UnexpectedMessage, "Received handshake data after connection closure");
            }
            process_handshake_ccs(m_record_buf, record.sequence(), record.type(), record.version(), epoch0_restart);
         } else if(record.type() == Record_Type::ApplicationData) {
            if(m_has_been_closed) {
               throw TLS_Exception(Alert::UnexpectedMessage, "Received application data after connection closure");
            }
            if(pending_state() != nullptr) {
               throw TLS_Exception(Alert::UnexpectedMessage, "Can't interleave application and handshake data");
            }
            process_application_data(record.sequence(), m_record_buf);
         } else if(record.type() == Record_Type::Alert) {
            process_alert(m_record_buf);
         } else if(record.type() != Record_Type::Invalid) {
            throw Unexpected_Message("Unexpected record type " + std::to_string(static_cast<size_t>(record.type())) +
                                     " from counterparty");
         }
      }

      return 0;  // on a record boundary
   } catch(TLS_Exception& e) {
      send_fatal_alert(e.type());
      throw;
   } catch(Invalid_Authentication_Tag&) {
      send_fatal_alert(Alert::BadRecordMac);
      throw;
   } catch(Decoding_Error&) {
      send_fatal_alert(Alert::DecodeError);
      throw;
   } catch(...) {
      send_fatal_alert(Alert::InternalError);
      throw;
   }
}

void Channel_Impl_12::process_handshake_ccs(const secure_vector<uint8_t>& record,
                                            uint64_t record_sequence,
                                            Record_Type record_type,
                                            Protocol_Version record_version,
                                            bool epoch0_restart) {
   const auto process_retransmitted_record = [&] {
      BOTAN_ASSERT(m_active_state.has_value(), "Have active DTLS association for retransmission");
      BOTAN_ASSERT_NONNULL(m_active_state->dtls_handshake_io());
      // Epoch-zero records are unauthenticated and may be spoofed, so a
      // malformed one must not tear down an established association.
      const bool unauthenticated = (record_sequence >> 48) == 0;

      absorb_malformed_input_errors(unauthenticated, [&] {
         m_active_state->dtls_handshake_io()->add_retransmitted_record(
            record.data(), record.size(), record_type, record_sequence);
      });
   };

   if(!m_pending_state) {
      // With no pending handshake this is either a new handshake attempt or a
      // DTLS retransmission from the previous handshake. The latter must not
      // create fresh pending state; it only asks us to replay our last flight.
      if(epoch0_restart && m_sequence_numbers && m_active_state.has_value()) {
         const bool starts_new_handshake = is_new_dtls_association_client_hello(record, record_type);

         if(!starts_new_handshake) {
            process_retransmitted_record();
            return;
         }
      }

      if(m_is_datagram && !epoch0_restart) {
         if(m_sequence_numbers) {
            const uint16_t epoch = record_sequence >> 48;
            const uint16_t current_epoch = sequence_numbers().current_read_epoch();
            if(epoch == current_epoch) {
               // Either endpoint can initiate renegotiation from FINISHED:
               // clients send ClientHello, servers send HelloRequest.
               const bool starts_new_handshake =
                  (record_type == Record_Type::Handshake && !record.empty() &&
                   (static_cast<Handshake_Type>(record[0]) == Handshake_Type::ClientHello ||
                    static_cast<Handshake_Type>(record[0]) == Handshake_Type::HelloRequest));

               if(m_active_state.has_value() && !starts_new_handshake) {
                  process_retransmitted_record();
               } else {
                  create_handshake_state(record_version);
               }
            } else if(current_epoch > 0 && epoch == current_epoch - 1) {
               process_retransmitted_record();
            }
         } else {
            create_handshake_state(record_version);
         }
      } else {
         create_handshake_state(record_version);
      }
   }

   // May have been created in above conditional
   if(m_pending_state) {
      // An epoch-zero record is unauthenticated. Once an association is
      // established, one arriving during a pending renegotiation must not be
      // able to destroy it, exactly as for the no-pending-handshake path above.
      // Without this a single forged CCS or handshake fragment tore down the
      // active association and the renegotiation along with it.
      //
      // Delivery is inside the guard as well as reassembly. A bare 12-byte
      // header declaring a zero-length message reassembles cleanly and only
      // fails when the message itself is parsed or dispatched, which reaches
      // the same teardown by a later route.
      const bool unauthenticated_against_active_association =
         m_is_datagram && (record_sequence >> 48) == 0 && m_active_state.has_value();

      absorb_malformed_input_errors(unauthenticated_against_active_association, [&] {
         m_pending_state->handshake_io().add_record(record.data(), record.size(), record_type, record_sequence);

         while(auto* pending = m_pending_state.get()) {
            auto msg = pending->get_next_handshake_msg(policy().maximum_handshake_message_size());

            if(msg.first == Handshake_Type::None) {  // no full handshake yet
               break;
            }

            process_handshake_msg(*pending, msg.first, msg.second, epoch0_restart);

            if(!m_pending_state) {
               break;
            }
         }
      });
   }
}

void Channel_Impl_12::process_application_data(uint64_t seq_no, const secure_vector<uint8_t>& record) {
   if(!m_active_state.has_value()) {
      throw Unexpected_Message("Application data before handshake done");
   }

   // ApplicationData must arrive under a non-zero read epoch
   const uint16_t read_epoch =
      m_is_datagram ? static_cast<uint16_t>(seq_no >> 48) : sequence_numbers().current_read_epoch();
   if(read_epoch == 0) {
      throw Unexpected_Message("Application data received in unexpected read epoch");
   }

   callbacks().tls_record_received(seq_no, record);
}

void Channel_Impl_12::process_alert(const secure_vector<uint8_t>& record) {
   const Alert alert_msg(record);

   // RFC 5246 7.2.2:
   //    no_renegotiation
   //       Sent by the client in response to a hello request or by the
   //       server in response to a client hello after initial handshaking.
   if(alert_msg.type() == Alert::NoRenegotiation && m_active_state.has_value()) {
      m_pending_state.reset();
   }

   if(alert_msg.is_fatal()) {
      // RFC 5246 7.2.2: "Upon transmission or receipt of a fatal alert message,
      // both parties immediately close the connection."
      //
      // The teardown completes before the application hears about the alert, so
      // the callback cannot reach the connection or its secrets. Same order as
      // the TLS 1.3 channel.
      m_has_been_closed = true;
      m_had_fatal_alert = true;
      const auto invalidated = take_sessions_to_invalidate();
      reset_state();
      invalidate_sessions(invalidated);
   }

   callbacks().tls_alert(alert_msg);

   if(alert_msg.type() == Alert::CloseNotify) {
      m_peer_closed_connection = true;

      // TLS 1.2 requires us to immediately react with our "close_notify",
      // the return value of the application's callback has no effect on that.
      callbacks().tls_peer_closed_connection();
      send_warning_alert(Alert::CloseNotify);  // reply in kind
   }

   if(alert_msg.type() == Alert::CloseNotify || alert_msg.is_fatal()) {
      m_has_been_closed = true;
   }
}

void Channel_Impl_12::write_record(Connection_Cipher_State* cipher_state,
                                   uint16_t epoch,
                                   Record_Type record_type,
                                   const uint8_t input[],
                                   size_t length) {
   BOTAN_ASSERT(m_pending_state || m_active_state.has_value(), "Some connection state exists");

   const Protocol_Version record_version = (m_pending_state) ? (m_pending_state->version()) : m_active_state->version();

   const uint64_t next_seq = sequence_numbers().next_write_sequence(epoch);

   if(cipher_state == nullptr) {
      TLS::write_unencrypted_record(m_writebuf, record_type, record_version, next_seq, input, length);
   } else {
      TLS::write_record(m_writebuf, record_type, record_version, next_seq, input, length, *cipher_state, rng());
   }

   callbacks().tls_emit_data(m_writebuf);
}

void Channel_Impl_12::send_record_array(uint16_t epoch, Record_Type type, const uint8_t input[], size_t length) {
   if(length == 0) {
      return;
   }

   auto cipher_state = write_cipher_state_epoch(epoch);

   while(length > 0) {
      const size_t sending = std::min<size_t>(length, MAX_PLAINTEXT_SIZE);
      write_record(cipher_state.get(), epoch, type, input, sending);

      input += sending;
      length -= sending;
   }
}

void Channel_Impl_12::send_record(Record_Type record_type, const std::vector<uint8_t>& record) {
   send_record_array(sequence_numbers().current_write_epoch(), record_type, record.data(), record.size());
}

void Channel_Impl_12::send_record_under_epoch(uint16_t epoch,
                                              Record_Type record_type,
                                              const std::vector<uint8_t>& record) {
   send_record_array(epoch, record_type, record.data(), record.size());
}

void Channel_Impl_12::to_peer(std::span<const uint8_t> data) {
   if(!is_active()) {
      throw Invalid_State("Data cannot be sent on inactive TLS connection");
   }

   send_record_array(sequence_numbers().current_write_epoch(), Record_Type::ApplicationData, data.data(), data.size());
}

void Channel_Impl_12::send_alert(const Alert& alert) {
   const bool ready_to_send_anything = !is_closed() && m_sequence_numbers;
   if(alert.is_valid() && ready_to_send_anything) {
      try {
         send_record(Record_Type::Alert, alert.serialize());
      } catch(...) { /* swallow it */
      }
   }

   if(alert.type() == Alert::NoRenegotiation && m_active_state.has_value()) {
      m_pending_state.reset();
   }

   if(alert.is_fatal()) {
      // Order matters: the channel is made unusable and its secrets destroyed
      // before any application-supplied storage is touched, so a throwing
      // session manager cannot leave is_active() true with live keys.
      m_had_fatal_alert = true;
      m_has_been_closed = true;

      // Alert::None is the local teardown that is never sent to the peer, used
      // where the trigger was unauthenticated input or a local timeout. Evicting
      // the resumption state on that basis would hand anyone able to reach the
      // address the ability to destroy it, which is what keeping the teardown
      // local exists to prevent.
      const auto invalidated =
         (alert.type() == Alert::None) ? std::vector<Session_Handle>() : take_sessions_to_invalidate();

      reset_state();
      invalidate_sessions(invalidated);
   }

   if(alert.type() == Alert::CloseNotify || alert.is_fatal()) {
      m_has_been_closed = true;
   }
}

void Channel_Impl_12::secure_renegotiation_check(const Client_Hello_12* client_hello) {
   BOTAN_ASSERT_NONNULL(client_hello);
   const bool secure_renegotiation = client_hello->secure_renegotiation();

   if(m_active_state && m_active_state->client_supports_secure_renegotiation() != secure_renegotiation) {
      throw TLS_Exception(Alert::HandshakeFailure, "Client changed its mind about secure renegotiation");
   }

   if(secure_renegotiation) {
      const std::vector<uint8_t>& data = client_hello->renegotiation_info();

      const auto expected = secure_renegotiation_data_for_client_hello();
      if(!CT::is_equal<uint8_t>(data, expected).as_bool()) {
         throw TLS_Exception(Alert::HandshakeFailure, "Client sent bad values for secure renegotiation");
      }
   }
}

void Channel_Impl_12::secure_renegotiation_check(const Server_Hello_12* server_hello) {
   BOTAN_ASSERT_NONNULL(server_hello);
   const bool secure_renegotiation = server_hello->secure_renegotiation();

   if(m_active_state && m_active_state->server_supports_secure_renegotiation() != secure_renegotiation) {
      throw TLS_Exception(Alert::HandshakeFailure, "Server changed its mind about secure renegotiation");
   }

   if(secure_renegotiation) {
      const std::vector<uint8_t>& data = server_hello->renegotiation_info();

      const auto expected = secure_renegotiation_data_for_server_hello();
      if(!CT::is_equal<uint8_t>(data, expected).as_bool()) {
         throw TLS_Exception(Alert::HandshakeFailure, "Server sent bad values for secure renegotiation");
      }
   }
}

std::vector<uint8_t> Channel_Impl_12::secure_renegotiation_data_for_client_hello() const {
   if(m_active_state.has_value()) {
      return m_active_state->client_finished_verify_data();
   }
   return std::vector<uint8_t>();
}

std::vector<uint8_t> Channel_Impl_12::secure_renegotiation_data_for_server_hello() const {
   if(m_active_state.has_value()) {
      return concat(m_active_state->client_finished_verify_data(), m_active_state->server_finished_verify_data());
   } else {
      return {};
   }
}

bool Channel_Impl_12::secure_renegotiation_supported() const {
   if(m_active_state.has_value()) {
      return m_active_state->server_supports_secure_renegotiation();
   }

   if(const auto* pending = pending_state()) {
      if(const auto* hello = pending->server_hello()) {
         return hello->secure_renegotiation();
      }
   }

   return false;
}

SymmetricKey Channel_Impl_12::key_material_export(std::string_view label,
                                                  std::string_view context,
                                                  size_t length) const {
   if(!m_active_state.has_value()) {
      throw Invalid_State("Channel_Impl_12::key_material_export connection not active");
   }

   // A fatal alert should have already cleared the active state:
   BOTAN_ASSERT_NOMSG(!m_had_fatal_alert);

   if(pending_state() != nullptr) {
      throw Invalid_State("Channel_Impl_12::key_material_export cannot export during renegotiation");
   }

   auto prf = callbacks().tls12_protocol_specific_kdf(m_active_state->prf_algo());

   const auto salt = [&] {
      if(context.empty()) {
         return concat(m_active_state->client_random(), m_active_state->server_random());
      } else {
         return concat(m_active_state->client_random(),
                       m_active_state->server_random(),
                       store_be(static_cast<uint16_t>(context.size())),
                       as_span_of_bytes(context));
      }
   }();

   return SymmetricKey(prf->derive_key(length, m_active_state->master_secret(), salt, as_span_of_bytes(label)));
}

}  // namespace Botan::TLS
