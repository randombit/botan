/*
* TLS Channel - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>

#include <botan/hash.h>
#include <botan/tls_messages.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>

#include <array>

namespace {
bool is_user_canceled_alert(const Botan::TLS::Alert& alert) {
   return alert.type() == Botan::TLS::Alert::UserCanceled;
}

bool is_close_notify_alert(const Botan::TLS::Alert& alert) {
   return alert.type() == Botan::TLS::Alert::CloseNotify;
}

bool is_error_alert(const Botan::TLS::Alert& alert) {
   // In TLS 1.3 all alerts except for closure alerts are considered error alerts.
   // (RFC 8446 6.)
   return !is_close_notify_alert(alert) && !is_user_canceled_alert(alert);
}
}  // namespace

namespace Botan::TLS {

Channel_Impl_13::Channel_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                                 const std::shared_ptr<Session_Manager>& session_manager,
                                 const std::shared_ptr<Credentials_Manager>& credentials_manager,
                                 const std::shared_ptr<RandomNumberGenerator>& rng,
                                 const std::shared_ptr<const Policy>& policy,
                                 bool is_server) :
      m_side(is_server ? Connection_Side::Server : Connection_Side::Client),
      m_callbacks(callbacks),
      m_session_manager(session_manager),
      m_credentials_manager(credentials_manager),
      m_rng(rng),
      m_policy(policy),
      m_record_layer(m_side),
      m_handshake_layer(m_side),
      m_can_read(true),
      m_can_write(true),
      m_opportunistic_key_update(false),
      m_first_message_sent(false),
      m_first_message_received(false) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_session_manager);
   BOTAN_ASSERT_NONNULL(m_credentials_manager);
   BOTAN_ASSERT_NONNULL(m_rng);
   BOTAN_ASSERT_NONNULL(m_policy);
}

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::from_peer(std::span<const uint8_t> data) {
   BOTAN_STATE_CHECK(!is_downgrading());

   // RFC 8446 6.1
   //    Any data received after a closure alert has been received MUST be ignored.
   if(!m_can_read) {
      return 0;
   }

   try {
      if(expects_downgrade()) {
         preserve_peer_transcript(data);
      }

      m_record_layer.copy_data(data);

      while(true) {
         // RFC 8446 6.1
         //    Any data received after a closure alert has been received MUST be ignored.
         //
         // ... this data might already be in the record layer's read buffer.
         if(!m_can_read) {
            return 0;
         }

         auto result = m_record_layer.next_record(m_cipher_state.get());

         if(std::holds_alternative<BytesNeeded>(result)) {
            return std::get<BytesNeeded>(result);
         }

         const auto& record = std::get<Record>(result);

         // RFC 8446 5.1
         //   Handshake messages MUST NOT be interleaved with other record types.
         if(record.type != Record_Type::Handshake && m_handshake_layer.has_pending_data()) {
            throw Unexpected_Message("Expected remainder of a handshake message");
         }

         if(record.type == Record_Type::Handshake) {
            m_handshake_layer.copy_data(record.fragment);

            if(!is_handshake_complete()) {
               while(auto handshake_msg = m_handshake_layer.next_message(policy(), m_transcript_hash)) {
                  // RFC 8446 5.1
                  //    Handshake messages MUST NOT span key changes.  Implementations
                  //    MUST verify that all messages immediately preceding a key change
                  //    align with a record boundary; if not, then they MUST terminate the
                  //    connection with an "unexpected_message" alert.  Because the
                  //    ClientHello, EndOfEarlyData, ServerHello, Finished, and KeyUpdate
                  //    messages can immediately precede a key change, implementations
                  //    MUST send these messages in alignment with a record boundary.
                  //
                  // Note: Hello_Retry_Request was added to the list below although it cannot immediately precede a key change.
                  //       However, there cannot be any further sensible messages in the record after HRR.
                  //
                  // Note: Server_Hello_12 was deliberately not included in the check below because in TLS 1.2 Server Hello and
                  //       other handshake messages can be legally coalesced in a single record.
                  //
                  if(holds_any_of<Client_Hello_12,
                                  Client_Hello_13 /*, EndOfEarlyData,*/,
                                  Server_Hello_13,
                                  Hello_Retry_Request,
                                  Finished_13>(handshake_msg.value()) &&
                     m_handshake_layer.has_pending_data()) {
                     throw Unexpected_Message("Unexpected additional handshake message data found in record");
                  }

                  process_handshake_msg(std::move(handshake_msg.value()));

                  if(is_downgrading()) {
                     // Downgrade to TLS 1.2 was detected. Stop everything we do and await being replaced by a 1.2 implementation.
                     return 0;
                  } else if(m_downgrade_info != nullptr) {
                     // We received a TLS 1.3 error alert that could have been a TLS 1.2 warning alert.
                     // Now that we know that we are talking to a TLS 1.3 server, shut down.
                     if(m_downgrade_info->received_tls_13_error_alert) {
                        shutdown();
                     }

                     // Downgrade can only be indicated in the first received peer message. This was not the case.
                     m_downgrade_info.reset();
                  }

                  // After the initial handshake message is received, the record
                  // layer must be more restrictive.
                  // See RFC 8446 5.1 regarding "legacy_record_version"
                  if(!m_first_message_received) {
                     m_record_layer.disable_receiving_compat_mode();
                     m_first_message_received = true;
                  }
               }
            } else {
               while(auto handshake_msg = m_handshake_layer.next_post_handshake_message(policy())) {
                  process_post_handshake_msg(std::move(handshake_msg.value()));
               }
            }
         } else if(record.type == Record_Type::ChangeCipherSpec) {
            process_dummy_change_cipher_spec();
         } else if(record.type == Record_Type::ApplicationData) {
            BOTAN_ASSERT(record.seq_no.has_value(), "decrypted application traffic had a sequence number");
            callbacks().tls_record_received(record.seq_no.value(), record.fragment);
         } else if(record.type == Record_Type::Alert) {
            process_alert(record.fragment);
         } else {
            throw Unexpected_Message("Unexpected record type " + std::to_string(static_cast<size_t>(record.type)) +
                                     " from counterparty");
         }
      }
   } catch(TLS_Exception& e) {
      send_fatal_alert(e.type());
      throw;
   } catch(Invalid_Authentication_Tag&) {
      // RFC 8446 5.2
      //    If the decryption fails, the receiver MUST terminate the connection
      //    with a "bad_record_mac" alert.
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

void Channel_Impl_13::handle(const Key_Update& key_update) {
   // make sure Key_Update appears only at the end of a record; see description above
   if(m_handshake_layer.has_pending_data()) {
      throw Unexpected_Message("Unexpected additional post-handshake message data found in record");
   }

   m_cipher_state->update_read_keys(*this);

   // TODO: introduce some kind of rate limit of key updates, otherwise we
   //       might be forced into an endless loop of key updates.

   // RFC 8446 4.6.3
   //    If the request_update field is set to "update_requested", then the
   //    receiver MUST send a KeyUpdate of its own with request_update set to
   //    "update_not_requested" prior to sending its next Application Data
   //    record.
   if(key_update.expects_reciprocation()) {
      // RFC 8446 4.6.3
      //    This mechanism allows either side to force an update to the
      //    multiple KeyUpdates while it is silent to respond with a single
      //    update.
      opportunistically_update_traffic_keys();
   }
}

Channel_Impl_13::AggregatedMessages::AggregatedMessages(Channel_Impl_13& channel, Handshake_Layer& handshake_layer) :
      m_channel(channel), m_handshake_layer(handshake_layer) {}

Channel_Impl_13::AggregatedHandshakeMessages::AggregatedHandshakeMessages(Channel_Impl_13& channel,
                                                                          Handshake_Layer& handshake_layer,
                                                                          Transcript_Hash_State& transcript_hash) :
      AggregatedMessages(channel, handshake_layer), m_transcript_hash(transcript_hash) {}

Channel_Impl_13::AggregatedHandshakeMessages& Channel_Impl_13::AggregatedHandshakeMessages::add(
   const Handshake_Message_13_Ref message) {
   std::visit([&](const auto msg) { m_channel.callbacks().tls_inspect_handshake_msg(msg.get()); }, message);
   m_message_buffer += m_handshake_layer.prepare_message(message, m_transcript_hash);
   return *this;
}

Channel_Impl_13::AggregatedPostHandshakeMessages& Channel_Impl_13::AggregatedPostHandshakeMessages::add(
   Post_Handshake_Message_13 message) {
   std::visit([&](const auto& msg) { m_channel.callbacks().tls_inspect_handshake_msg(msg); }, message);
   m_message_buffer += m_handshake_layer.prepare_post_handshake_message(message);
   return *this;
}

std::vector<uint8_t> Channel_Impl_13::AggregatedMessages::send() {
   BOTAN_STATE_CHECK(contains_messages());
   m_channel.send_record(Record_Type::Handshake, m_message_buffer);
   return std::exchange(m_message_buffer, {});
}

void Channel_Impl_13::send_dummy_change_cipher_spec() {
   // RFC 8446 5.
   //    The change_cipher_spec record is used only for compatibility purposes
   //    (see Appendix D.4).
   //
   // The only allowed CCS message content is 0x01, all other CCS records MUST
   // be rejected by TLS 1.3 implementations.
   send_record(Record_Type::ChangeCipherSpec, {0x01});
}

void Channel_Impl_13::to_peer(std::span<const uint8_t> data) {
   if(!is_active()) {
      throw Invalid_State("Data cannot be sent on inactive TLS connection");
   }

   // RFC 8446 4.6.3
   //    If the request_update field [of a received KeyUpdate] is set to
   //    "update_requested", then the receiver MUST send a KeyUpdate of its own
   //    with request_update set to "update_not_requested" prior to sending its
   //    next Application Data record.
   //    This mechanism allows either side to force an update to the entire
   //    connection, but causes an implementation which receives multiple
   //    KeyUpdates while it is silent to respond with a single update.
   if(m_opportunistic_key_update) {
      update_traffic_keys(false /* update_requested */);
      m_opportunistic_key_update = false;
   }

   send_record(Record_Type::ApplicationData, {data.begin(), data.end()});
}

void Channel_Impl_13::send_alert(const Alert& alert) {
   if(alert.is_valid() && m_can_write) {
      try {
         send_record(Record_Type::Alert, alert.serialize());
      } catch(...) { /* swallow it */
      }
   }

   // Note: In TLS 1.3 sending a CloseNotify must not immediately lead to closing the reading end.
   // RFC 8446 6.1
   //    Each party MUST send a "close_notify" alert before closing its write
   //    side of the connection, unless it has already sent some error alert.
   //    This does not have any effect on its read side of the connection.
   if(is_close_notify_alert(alert) && m_can_write) {
      m_can_write = false;
      if(m_cipher_state) {
         m_cipher_state->clear_write_keys();
      }
   }

   if(is_error_alert(alert)) {
      shutdown();
   }
}

bool Channel_Impl_13::is_active() const {
   return m_cipher_state != nullptr && m_cipher_state->can_encrypt_application_traffic()  // handshake done
          && m_can_write;                                                                 // close() hasn't been called
}

SymmetricKey Channel_Impl_13::key_material_export(std::string_view label,
                                                  std::string_view context,
                                                  size_t length) const {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_cipher_state != nullptr && m_cipher_state->can_export_keys());
   return SymmetricKey(m_cipher_state->export_key(label, context, length));
}

void Channel_Impl_13::update_traffic_keys(bool request_peer_update) {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(is_handshake_complete());
   BOTAN_ASSERT_NONNULL(m_cipher_state);
   send_post_handshake_message(Key_Update(request_peer_update));
   m_cipher_state->update_write_keys(*this);
}

void Channel_Impl_13::send_record(Record_Type type, const std::vector<uint8_t>& record) {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_can_write);

   auto to_write = m_record_layer.prepare_records(type, record, m_cipher_state.get());

   // After the initial handshake message is sent, the record layer must
   // adhere to a more strict record specification. Note that for the
   // server case this is a NOOP.
   // See (RFC 8446 5.1. regarding "legacy_record_version")
   if(!m_first_message_sent && type == Record_Type::Handshake) {
      m_record_layer.disable_sending_compat_mode();
      m_first_message_sent = true;
   }

   // The dummy CCS must not be prepended if the following record is
   // an unprotected Alert record.
   if(prepend_ccs() && (m_cipher_state || type != Record_Type::Alert)) {
      std::array<uint8_t, 1> ccs_content = {0x01};
      const auto ccs = m_record_layer.prepare_records(Record_Type::ChangeCipherSpec, ccs_content, m_cipher_state.get());
      to_write = concat(ccs, to_write);
   }

   callbacks().tls_emit_data(to_write);
}

void Channel_Impl_13::process_alert(const secure_vector<uint8_t>& record) {
   Alert alert(record);

   if(is_close_notify_alert(alert)) {
      m_can_read = false;
      if(m_cipher_state) {
         m_cipher_state->clear_read_keys();
      }
      m_record_layer.clear_read_buffer();
   }

   // user canceled alerts are ignored

   // RFC 8446 5.
   //    All the alerts listed in Section 6.2 MUST be sent with
   //    AlertLevel=fatal and MUST be treated as error alerts when received
   //    regardless of the AlertLevel in the message.  Unknown Alert types
   //    MUST be treated as error alerts.
   if(is_error_alert(alert) && !alert.is_fatal()) {
      // In TLS 1.2 error alerts might be marked as 'warnings' and would not
      // demand an immediate shutdown. Until we are sure to talk to a TLS 1.3
      // peer we must defer the shutdown and refrain from raising a decode
      // error.
      if(expects_downgrade()) {
         m_downgrade_info->received_tls_13_error_alert = true;
      } else {
         throw TLS_Exception(Alert::DecodeError, "Error alert not marked fatal");  // will shutdown in send_alert
      }
   }

   if(alert.is_fatal()) {
      shutdown();
   }

   callbacks().tls_alert(alert);

   // Respond with our "close_notify" if the application requests us to.
   if(is_close_notify_alert(alert) && callbacks().tls_peer_closed_connection()) {
      close();
   }
}

void Channel_Impl_13::shutdown() {
   // RFC 8446 6.2
   //    Upon transmission or receipt of a fatal alert message, both
   //    parties MUST immediately close the connection.
   m_can_read = false;
   m_can_write = false;
   m_cipher_state.reset();
}

void Channel_Impl_13::expect_downgrade(const Server_Information& server_info,
                                       const std::vector<std::string>& next_protocols) {
   Downgrade_Information di{
      {},
      {},
      {},
      server_info,
      next_protocols,
      Botan::TLS::Channel::IO_BUF_DEFAULT_SIZE,
      m_callbacks,
      m_session_manager,
      m_credentials_manager,
      m_rng,
      m_policy,
      false,  // received_tls_13_error_alert
      false   // will_downgrade
   };
   m_downgrade_info = std::make_unique<Downgrade_Information>(std::move(di));
}

void Channel_Impl_13::set_record_size_limits(const uint16_t outgoing_limit, const uint16_t incoming_limit) {
   m_record_layer.set_record_size_limits(outgoing_limit, incoming_limit);
}

void Channel_Impl_13::set_selected_certificate_type(const Certificate_Type cert_type) {
   m_handshake_layer.set_selected_certificate_type(cert_type);
}

}  // namespace Botan::TLS
