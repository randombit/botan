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
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/stl_util.h>
#include <botan/tls_messages.h>

namespace {
bool is_user_canceled_alert(const Botan::TLS::Alert& alert)
   {
   return alert.type() == Botan::TLS::Alert::USER_CANCELED;
   }

bool is_close_notify_alert(const Botan::TLS::Alert& alert)
   {
   return alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY;
   }

bool is_error_alert(const Botan::TLS::Alert& alert)
   {
   // In TLS 1.3 all alerts except for closure alerts are considered error alerts.
   // (RFC 8446 6.)
   return !is_close_notify_alert(alert) && !is_user_canceled_alert(alert);
   }
}

namespace Botan::TLS {

Channel_Impl_13::Channel_Impl_13(Callbacks& callbacks,
                                 Session_Manager& session_manager,
                                 Credentials_Manager& credentials_manager,
                                 RandomNumberGenerator& rng,
                                 const Policy& policy,
                                 bool is_server) :
   m_side(is_server ? Connection_Side::SERVER : Connection_Side::CLIENT),
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_credentials_manager(credentials_manager),
   m_rng(rng),
   m_policy(policy),
   m_record_layer(m_side),
   m_handshake_layer(m_side),
   m_can_read(true),
   m_can_write(true),
   m_opportunistic_key_update(false)
   {
   }

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::received_data(const uint8_t input[], size_t input_size)
   {
   BOTAN_STATE_CHECK(!is_downgrading());

   // RFC 8446 6.1
   //    Any data received after a closure alert has been received MUST be ignored.
   if(!m_can_read)
      { return 0; }

   try
      {
      if(expects_downgrade())
         { preserve_peer_transcript(input, input_size); }

      m_record_layer.copy_data(input, input_size);

      while(true)
         {
         // RFC 8446 6.1
         //    Any data received after a closure alert has been received MUST be ignored.
         //
         // ... this data might already be in the record layer's read buffer.
         if(!m_can_read)
            { return 0; }

         auto result = m_record_layer.next_record(m_cipher_state.get());

         if(std::holds_alternative<BytesNeeded>(result))
            { return std::get<BytesNeeded>(result); }

         const auto& record = std::get<Record>(result);

         // RFC 8446 5.1
         //   Handshake messages MUST NOT be interleaved with other record types.
         if(record.type != HANDSHAKE && m_handshake_layer.has_pending_data())
            { throw Unexpected_Message("Expected remainder of a handshake message"); }

         if(record.type == HANDSHAKE)
            {
            m_handshake_layer.copy_data(unlock(record.fragment));  // TODO: record fragment should be an ordinary std::vector

            if(!handshake_finished())
               {
               while(auto handshake_msg = m_handshake_layer.next_message(policy(), m_transcript_hash))
                  {
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
                  if(holds_any_of<Client_Hello_13/*, EndOfEarlyData,*/, Server_Hello_13, Hello_Retry_Request, Finished_13>
                        (handshake_msg.value())
                        && m_handshake_layer.has_pending_data())
                     { throw Unexpected_Message("Unexpected additional handshake message data found in record"); }

                  const bool downgrade_requested = std::holds_alternative<Server_Hello_12>(handshake_msg.value());

                  process_handshake_msg(std::move(handshake_msg.value()));

                  if(downgrade_requested)
                     {
                     // Downgrade to TLS 1.2 was detected. Stop everything we do and await being replaced by a 1.2 implementation.
                     BOTAN_STATE_CHECK(m_downgrade_info);
                     m_downgrade_info->will_downgrade = true;
                     return 0;
                     }
                  else if(m_downgrade_info != nullptr)
                     {
                     // We received a TLS 1.3 error alert that could have been a TLS 1.2 warning alert.
                     // Now that we know that we are talking to a TLS 1.3 server, shut down.
                     if(m_downgrade_info->received_tls_13_error_alert)
                        shutdown();

                     // Downgrade can only happen if the first received message is a Server_Hello_12. This was not the case.
                     m_downgrade_info.reset();
                     }
                  }
               }
            else
               {
               while(auto handshake_msg = m_handshake_layer.next_post_handshake_message(policy()))
                  {
                  // make sure Key_Update appears only at the end of a record; see description above
                  if(std::holds_alternative<Key_Update>(handshake_msg.value()) && m_handshake_layer.has_pending_data())
                     { throw Unexpected_Message("Unexpected additional post-handshake message data found in record"); }

                  process_post_handshake_msg(std::move(handshake_msg.value()));
                  }
               }
            }
         else if(record.type == CHANGE_CIPHER_SPEC)
            {
            process_dummy_change_cipher_spec();
            }
         else if(record.type == APPLICATION_DATA)
            {
            BOTAN_ASSERT(record.seq_no.has_value(), "decrypted application traffic had a sequence number");
            callbacks().tls_record_received(record.seq_no.value(), record.fragment.data(), record.fragment.size());
            }
         else if(record.type == ALERT)
            {
            process_alert(record.fragment);
            }
         else
            { throw Unexpected_Message("Unexpected record type " + std::to_string(record.type) + " from counterparty"); }
         }
      }
   catch(TLS_Exception& e)
      {
      send_fatal_alert(e.type());
      throw;
      }
   catch(Invalid_Authentication_Tag&)
      {
      // RFC 8446 5.2
      //    If the decryption fails, the receiver MUST terminate the connection
      //    with a "bad_record_mac" alert.
      send_fatal_alert(Alert::BAD_RECORD_MAC);
      throw;
      }
   catch(Decoding_Error&)
      {
      send_fatal_alert(Alert::DECODE_ERROR);
      throw;
      }
   catch(...)
      {
      send_fatal_alert(Alert::INTERNAL_ERROR);
      throw;
      }
   }

void Channel_Impl_13::send_handshake_message(const Handshake_Message_13_Ref message)
   {
   std::visit([&](const auto msg) { callbacks().tls_inspect_handshake_msg(msg.get()); }, message);

   auto msg = m_handshake_layer.prepare_message(message, m_transcript_hash);

   if(expects_downgrade() && std::holds_alternative<std::reference_wrapper<Client_Hello_13>>(message))
      { preserve_client_hello(msg); }

   send_record(Record_Type::HANDSHAKE, msg);
   }

void Channel_Impl_13::send_post_handshake_message(const Post_Handshake_Message_13 message)
   {
   send_record(Record_Type::HANDSHAKE, m_handshake_layer.prepare_post_handshake_message(message));
   }

void Channel_Impl_13::send_dummy_change_cipher_spec()
   {
   // RFC 8446 5.
   //    The change_cipher_spec record is used only for compatibility purposes
   //    (see Appendix D.4).
   //
   // The only allowed CCS message content is 0x01, all other CCS records MUST
   // be rejected by TLS 1.3 implementations.
   send_record(Record_Type::CHANGE_CIPHER_SPEC, {0x01});
   }

void Channel_Impl_13::send(const uint8_t buf[], size_t buf_size)
   {
   if(!is_active())
      { throw Invalid_State("Data cannot be sent on inactive TLS connection"); }

   // RFC 8446 4.6.3
   //    If the request_update field [of a received KeyUpdate] is set to
   //    "update_requested", then the receiver MUST send a KeyUpdate of its own
   //    with request_update set to "update_not_requested" prior to sending its
   //    next Application Data record.
   //    This mechanism allows either side to force an update to the entire
   //    connection, but causes an implementation which receives multiple
   //    KeyUpdates while it is silent to respond with a single update.
   if(m_opportunistic_key_update)
      {
      update_traffic_keys(false /* update_requested */);
      m_opportunistic_key_update = false;
      }

   send_record(Record_Type::APPLICATION_DATA, {buf, buf+buf_size});
   }

void Channel_Impl_13::send_alert(const Alert& alert)
   {
   if(alert.is_valid() && m_can_write)
      {
      try
         {
         send_record(Record_Type::ALERT, alert.serialize());
         }
      catch(...) { /* swallow it */ }
      }

   // Note: In TLS 1.3 sending a CLOSE_NOTIFY must not immediately lead to closing the reading end.
   // RFC 8446 6.1
   //    Each party MUST send a "close_notify" alert before closing its write
   //    side of the connection, unless it has already sent some error alert.
   //    This does not have any effect on its read side of the connection.
   if(is_close_notify_alert(alert))
      {
      m_can_write = false;
      m_cipher_state->clear_write_keys();
      }

   if(is_error_alert(alert))
      { shutdown(); }
   }

bool Channel_Impl_13::is_active() const
   {
   return
      m_cipher_state != nullptr && m_cipher_state->can_encrypt_application_traffic() // handshake done
      && m_can_write;  // close() hasn't been called
   }

SymmetricKey Channel_Impl_13::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_cipher_state != nullptr && m_cipher_state->can_export_keys());
   return m_cipher_state->export_key(label, context, length);
   }

void Channel_Impl_13::update_traffic_keys(bool request_peer_update)
   {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(handshake_finished());
   send_post_handshake_message(Key_Update(request_peer_update));
   m_cipher_state->update_write_keys();
   }

void Channel_Impl_13::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_can_write);

   auto to_write = m_record_layer.prepare_records(static_cast<Record_Type>(record_type), record, m_cipher_state.get());

   if(prepend_ccs())
      {
      const auto ccs = m_record_layer.prepare_records(Record_Type::CHANGE_CIPHER_SPEC, {0x01}, m_cipher_state.get());
      to_write = concat(ccs, to_write);
      }

   callbacks().tls_emit_data(to_write.data(), to_write.size());
   }

void Channel_Impl_13::process_alert(const secure_vector<uint8_t>& record)
   {
   Alert alert(record);

   if(is_close_notify_alert(alert))
      {
      m_can_read = false;
      m_cipher_state->clear_read_keys();
      m_record_layer.clear_read_buffer();
      }

   // user canceled alerts are ignored

   // TODO: the server doesn't have to expect downgrading; move this to the client
   if(!expects_downgrade())
      {
      // RFC 8446 5.
      //    All the alerts listed in Section 6.2 MUST be sent with
      //    AlertLevel=fatal and MUST be treated as error alerts when received
      //    regardless of the AlertLevel in the message.  Unknown Alert types
      //    MUST be treated as error alerts.
      if(is_error_alert(alert) && !alert.is_fatal())
         {
         throw TLS_Exception(Alert::DECODE_ERROR, "Error alert not marked fatal");  // will shutdown in send_alert
         }
      }
   else
      {
      // Don't immediately shut down in case we might be dealing with a TLS 1.2 server. In this case,
      // we cannot immediately shut down on alerts that are warnings in TLS 1.2.
      // However, if the server turns out to _not_ downgrade, treat this as an error and do shut down.
      // Note that this should not happen with a valid implementation, as the TLS 1.3 server shouldn't
      // send a SERVER HELLO after the alert.
      if(is_error_alert(alert))
         m_downgrade_info->received_tls_13_error_alert = true;
      }

   if(alert.is_fatal())
      shutdown();

   callbacks().tls_alert(alert);
   }

void Channel_Impl_13::shutdown()
   {
   // RFC 8446 6.2
   //    Upon transmission or receipt of a fatal alert message, both
   //    parties MUST immediately close the connection.
   m_can_read = false;
   m_can_write = false;
   m_cipher_state.reset();
   }

void Channel_Impl_13::expect_downgrade(const Server_Information& server_info)
   {
   Downgrade_Information di
      {
         {},
         {},
      server_info,
      callbacks(),
      session_manager(),
      credentials_manager(),
      rng(),
      policy(),
      false, // received_tls_13_error_alert
      false  // will_downgrade
      };
   m_downgrade_info = std::make_unique<Downgrade_Information>(std::move(di));
   }

void Channel_Impl_13::set_record_size_limits(const uint16_t outgoing_limit,
                                             const uint16_t incoming_limit)
   {
   m_record_layer.set_record_size_limits(outgoing_limit, incoming_limit);
   }

}
