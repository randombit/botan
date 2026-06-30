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

bool is_new_dtls_association_client_hello(std::span<const uint8_t> record, Record_Type record_type) {
   constexpr size_t DTLS_HANDSHAKE_HEADER_SIZE = 12;

   // Every new DTLS handshake starts at message_seq 0. A cookie-bearing
   // ClientHello uses message_seq 1, so one arriving late belongs to the
   // previous handshake and must not replace the active association's state.
   return record_type == Record_Type::Handshake && record.size() >= DTLS_HANDSHAKE_HEADER_SIZE &&
          static_cast<Handshake_Type>(record[0]) == Handshake_Type::ClientHello && load_be(record.subspan<4, 2>()) == 0;
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
   m_read_cipher_states[0] = nullptr;

   m_writebuf.reserve(reserved_io_buffer_size);
   m_readbuf.reserve(reserved_io_buffer_size);
}

void Channel_Impl_12::reset_state() {
   m_active_state.reset();
   m_pending_state.reset();
   m_readbuf.clear();
   m_write_cipher_states.clear();
   m_read_cipher_states.clear();
}

void Channel_Impl_12::reset_active_association_state() {
   // This operation only makes sense for DTLS
   BOTAN_ASSERT_NOMSG(m_is_datagram);
   m_active_state.reset();
   m_read_cipher_states.clear();
   m_write_cipher_states.clear();

   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = nullptr;

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
   return i->second;
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

   using namespace std::placeholders;

   std::unique_ptr<Handshake_IO> io;
   if(version.is_datagram_protocol()) {
      const uint16_t mtu = static_cast<uint16_t>(policy().dtls_default_mtu());
      const size_t initial_timeout_ms = policy().dtls_initial_timeout();
      const size_t max_timeout_ms = policy().dtls_maximum_timeout();

      auto send_record_f = [this](uint16_t epoch, Record_Type record_type, const std::vector<uint8_t>& record) {
         send_record_under_epoch(epoch, record_type, record);
      };
      io = std::make_unique<Datagram_Handshake_IO>(send_record_f,
                                                   sequence_numbers(),
                                                   mtu,
                                                   initial_timeout_ms,
                                                   max_timeout_ms,
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

Handshake_IO* Channel_Impl_12::retransmission_io() {
   return const_cast<Handshake_IO*>(std::as_const(*this).retransmission_io());
}

const Handshake_IO* Channel_Impl_12::retransmission_io() const {
   if(!m_is_datagram || m_has_been_closed) {
      return nullptr;
   }

   if(m_pending_state) {
      return &m_pending_state->handshake_io();
   }

   // Until protected application data confirms that the peer processed our
   // final flight, keep it eligible for timeout-driven retransmission.
   if(m_active_state.has_value() && !m_active_state->peer_has_progressed()) {
      return m_active_state->dtls_handshake_io();
   }

   return nullptr;
}

bool Channel_Impl_12::timeout_check() {
   if(auto* io = retransmission_io()) {
      return io->timeout_check();
   }

   //FIXME: scan cipher suites and remove epochs older than 2*MSL
   return false;
}

void Channel_Impl_12::renegotiate(bool force_full_renegotiation) {
   if(pending_state() != nullptr) {  // currently in handshake?
      return;
   }

   if(m_active_state.has_value()) {
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

   m_read_cipher_states[epoch] = read_state;
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
}

bool Channel_Impl_12::is_handshake_complete() const {
   return m_active_state.has_value();
}

bool Channel_Impl_12::is_active() const {
   return !is_closed() && is_handshake_complete();
}

std::optional<std::chrono::milliseconds> Channel_Impl_12::next_retransmission_timeout() const {
   if(const auto* io = retransmission_io()) {
      return io->next_retransmission_timeout();
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

   // For DTLS, keep the handshake IO for last-flight retransmission.
   if(m_is_datagram) {
      m_active_state = Active_Connection_State_12(state, application_protocol(), m_pending_state->take_handshake_io());
      if(auto* dtls_io = m_active_state->dtls_handshake_io()) {
         // Mark the just-sent flight complete so timeout_check() may
         // retransmit it if the peer never receives it.
         dtls_io->finalize_handshake();
      }
   } else {
      m_active_state = Active_Connection_State_12(state, application_protocol());
   }

   m_pending_state.reset();

   callbacks().tls_session_activated();
}

size_t Channel_Impl_12::from_peer(std::span<const uint8_t> data) {
   const bool allow_epoch0_restart = m_is_datagram && m_is_server && policy().allow_dtls_epoch0_restart();

   const auto* input = data.data();
   auto input_size = data.size();

   try {
      while(input_size > 0) {
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

         if(m_record_buf.size() > MAX_PLAINTEXT_SIZE) {
            throw TLS_Exception(Alert::RecordOverflow, "TLS plaintext record is larger than allowed maximum");
         }

         const bool epoch0_restart = m_is_datagram && record.epoch() == 0 && m_active_state.has_value();
         BOTAN_ASSERT_IMPLICATION(epoch0_restart, allow_epoch0_restart, "Allowed state");

         const bool initial_record = epoch0_restart || (pending_state() == nullptr && !m_active_state.has_value());
         bool initial_handshake_message = false;
         if(record.type() == Record_Type::Handshake && !m_record_buf.empty()) {
            const Handshake_Type type = static_cast<Handshake_Type>(m_record_buf[0]);
            initial_handshake_message = (type == Handshake_Type::ClientHello);
         }

         if(record.type() != Record_Type::Alert) {
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
   if(!m_pending_state) {
      // With no pending handshake this is either a new handshake attempt or a
      // DTLS retransmission from the previous handshake. The latter must not
      // create fresh pending state; it only asks us to replay our last flight.
      if(record_version.is_datagram_protocol() && epoch0_restart && m_sequence_numbers && m_active_state.has_value()) {
         const bool starts_new_handshake = is_new_dtls_association_client_hello(record, record_type);

         if(!starts_new_handshake) {
            BOTAN_ASSERT_NONNULL(m_active_state->dtls_handshake_io());
            m_active_state->dtls_handshake_io()->add_retransmitted_record(
               record.data(), record.size(), record_type, record_sequence);
            return;
         }
      }

      if(record_version.is_datagram_protocol() && !epoch0_restart) {
         if(m_sequence_numbers) {
            sequence_numbers().read_accept(record_sequence);

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
                  BOTAN_ASSERT_NONNULL(m_active_state->dtls_handshake_io());
                  m_active_state->dtls_handshake_io()->add_retransmitted_record(
                     record.data(), record.size(), record_type, record_sequence);
                  return;
               } else {
                  create_handshake_state(record_version);
               }
            } else if(current_epoch > 0 && epoch == current_epoch - 1) {
               BOTAN_ASSERT(m_active_state.has_value(), "Have active DTLS association for retransmission");
               BOTAN_ASSERT_NONNULL(m_active_state->dtls_handshake_io());
               m_active_state->dtls_handshake_io()->add_retransmitted_record(
                  record.data(), record.size(), record_type, record_sequence);
               return;
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

   if(m_is_datagram) {
      m_active_state->mark_peer_as_progressed();
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

   callbacks().tls_alert(alert_msg);

   // If the alert is fatal on an active session, prevent later resumptions
   if(alert_msg.is_fatal() && m_active_state.has_value()) {
      const auto& sid = m_active_state->session_id();
      if(!sid.empty()) {
         session_manager().remove(Session_Handle(sid));
      }
   }

   if(alert_msg.type() == Alert::CloseNotify) {
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
      if(m_active_state.has_value()) {
         const auto& sid = m_active_state->session_id();
         if(!sid.empty()) {
            session_manager().remove(Session_Handle(sid));
         }
      }
      reset_state();
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
