/*
* TLS Channel - implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages_13.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_channel_io.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_transcript_hash_13.h>

#include <utility>

namespace Botan::TLS {

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

Channel_Impl_13::Channel_Impl_13(const std::shared_ptr<Callbacks>& callbacks,
                                 const std::shared_ptr<Session_Manager>& session_manager,
                                 const std::shared_ptr<Credentials_Manager>& credentials_manager,
                                 const std::shared_ptr<RandomNumberGenerator>& rng,
                                 const std::shared_ptr<const Policy>& policy,
                                 bool is_server) :
      m_side(is_server ? Connection_Side::Server : Connection_Side::Client),
      m_transcript_hash(TLS_Flavor::TLS),
      m_channel_io(Channel_IO::create(m_side, TLS_Flavor::TLS, policy, callbacks)),
      m_callbacks(callbacks),
      m_session_manager(session_manager),
      m_credentials_manager(credentials_manager),
      m_rng(rng),
      m_policy(policy),
      m_can_read(true),
      m_can_write(true) {
   BOTAN_ASSERT_NONNULL(m_callbacks);
   BOTAN_ASSERT_NONNULL(m_session_manager);
   BOTAN_ASSERT_NONNULL(m_credentials_manager);
   BOTAN_ASSERT_NONNULL(m_rng);
   BOTAN_ASSERT_NONNULL(m_policy);
}

Cipher_State& Channel_Impl_13::setup_cipher_state(std::unique_ptr<Cipher_State> cipher_state) {
   BOTAN_ASSERT_NONNULL(cipher_state);
   m_cipher_state = std::move(cipher_state);
   m_channel_io->set_cipher_state(m_cipher_state);
   return *m_cipher_state;
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
#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
      if(expects_downgrade()) {
         preserve_peer_transcript(data);
      }
#endif

      // First, ingest all incoming data...
      m_channel_io->copy_data(data);

      // ... then, process all pending events (i.e. decoded handshake messages,
      // alerts, application data, etc.) until we either run out of events and
      // have to wait for more data, or we encounter an exception and terminate.
      while(true) {
         // RFC 8446 6.1
         //    Any data received after a closure alert has been received MUST be ignored.
         //
         // ... this data might already be in the record layer's read buffer.
         if(!m_can_read) {
            return 0;
         }

         const auto bytes_needed = std::visit(  //
            overloaded{
               [](BytesNeeded bytes) -> std::optional<BytesNeeded> { return bytes; },
               [&]<typename T>(T&& event) -> std::optional<BytesNeeded> {
                  constexpr bool can_report_bytes_needed =
                     std::is_same_v<std::optional<BytesNeeded>, decltype(process(std::forward<T>(event)))>;
                  if constexpr(can_report_bytes_needed) {
                     return process(std::forward<T>(event));
                  } else {
                     process(std::forward<T>(event));
                     return {};
                  }
               },
            },
            m_channel_io->next_pending_event(m_transcript_hash, is_handshake_complete()));

         if(bytes_needed.has_value()) {
            return *bytes_needed;
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
   m_channel_io->handle_key_update(key_update);
}

void Channel_Impl_13::to_peer(std::span<const uint8_t> data) {
   BOTAN_STATE_CHECK(!is_downgrading());

   if(!is_active()) {
      throw Invalid_State("Data cannot be sent on inactive TLS connection");
   }

   m_channel_io->send(data);
}

void Channel_Impl_13::send_alert(const Alert& alert) {
   if(alert.is_valid() && m_can_write) {
      try {
         m_channel_io->send(alert, compat_mode_ccs_requested());
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
   BOTAN_STATE_CHECK(!is_downgrading() && is_handshake_complete() && is_active());
   m_channel_io->update_traffic_keys(request_peer_update);
}

SecretLoggerFn Channel_Impl_13::secret_logger() const {
   return [weak = weak_from_this()](std::string_view label, std::span<const uint8_t> secret) {
      if(const auto self = dynamic_pointer_cast<const Channel_Impl_13>(weak.lock())) {
         self->maybe_log_secret(label, secret);
      };
   };
}

void Channel_Impl_13::send_flight(std::vector<Flight::Message> flight) {
   BOTAN_STATE_CHECK(!flight.empty());
   BOTAN_STATE_CHECK(!is_downgrading());
   BOTAN_STATE_CHECK(m_can_write);

   m_channel_io->send(std::move(flight));
}

std::optional<BytesNeeded> Channel_Impl_13::process(Handshake_Message_13 handshake_msg) {
   process_handshake_msg(std::move(handshake_msg));

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
   if(is_downgrading()) {
      // Downgrade to TLS 1.2 was detected. Stop everything we do and await
      // being replaced by a 1.2 implementation.
      return 0;
   }
   if(m_downgrade_info != nullptr) {
      // We received a TLS 1.3 error alert that could have been a TLS 1.2 warning alert.
      // Now that we know that we are talking to a TLS 1.3 server, shut down.
      if(m_downgrade_info->received_tls_13_error_alert) {
         shutdown();
      }

      // Downgrade can only be indicated in the first received peer message. This was not the case.
      m_downgrade_info.reset();
   }
#endif

   return {};
}

void Channel_Impl_13::process(Post_Handshake_Message_13 post_handshake_msg) {
   process_post_handshake_msg(std::move(post_handshake_msg));
}

void Channel_Impl_13::process(const Alert_Record& alert_record) {
   const Alert alert(alert_record.payload);

   if(is_close_notify_alert(alert)) {
      m_can_read = false;
      if(m_cipher_state) {
         m_cipher_state->clear_read_keys();
      }
      m_channel_io->notify_closed_for_reading();
   }

   // user canceled alerts are ignored

   // RFC 8446 5.
   //    All the alerts listed in Section 6.2 MUST be sent with
   //    AlertLevel=fatal and MUST be treated as error alerts when received
   //    regardless of the AlertLevel in the message.  Unknown Alert types
   //    MUST be treated as error alerts.
   if(is_error_alert(alert) && !alert.is_fatal()) {
      if(!expects_downgrade()) {
         throw TLS_Exception(Alert::DecodeError, "Error alert not marked fatal");
      }

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)
      BOTAN_DEBUG_ASSERT(expects_downgrade());

      // In TLS 1.2 error alerts might be marked as 'warnings' and would not
      // demand an immediate shutdown. Until we are sure to talk to a TLS 1.3
      // peer we must defer the shutdown and refrain from raising a decode
      // error.
      m_downgrade_info->received_tls_13_error_alert = true;
#endif
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

void Channel_Impl_13::process(const ChangeCipherSpec_Record& ccs_record) {
   BOTAN_UNUSED(ccs_record);
   process_dummy_change_cipher_spec();
}

void Channel_Impl_13::process(const ApplicationData_Record& record) {
   BOTAN_ASSERT_NOMSG(record.sequence_number.has_value());
   BOTAN_ASSERT_NONNULL(m_cipher_state);
   if(!m_cipher_state->can_decrypt_application_traffic()) {
      throw Unexpected_Message("Application data received before handshake completion");
   }
   callbacks().tls_record_received(record.sequence_number.value(), record.payload);
}

void Channel_Impl_13::shutdown() {
   // RFC 8446 6.2
   //    Upon transmission or receipt of a fatal alert message, both
   //    parties MUST immediately close the connection.
   m_can_read = false;
   m_can_write = false;
   m_cipher_state.reset();
   m_active_state.reset();
}

#if defined(BOTAN_HAS_TLS_DOWNGRADE_SUPPORT)

void Channel_Impl_13::expect_downgrade(const Server_Information& server_info,
                                       const std::vector<std::string>& next_protocols) {
   Downgrade_Information di{
      {},
      {},
      {},
      server_info,
      next_protocols,
      Botan::TLS::Channel::IO_BUF_DEFAULT_SIZE,
      {},
      m_callbacks,
      m_session_manager,
      m_credentials_manager,
      m_rng,
      m_policy,
      TLS_Flavor::TLS,
      false,  // received_tls_13_error_alert
      false   // will_downgrade
   };
   m_downgrade_info = std::make_unique<Downgrade_Information>(std::move(di));
}

#endif

void Channel_Impl_13::set_record_size_limits(const uint16_t outgoing_limit, const uint16_t incoming_limit) {
   m_channel_io->set_record_size_limits(outgoing_limit, incoming_limit);
}

void Channel_Impl_13::set_selected_certificate_type(const Certificate_Type cert_type) {
   m_channel_io->set_selected_certificate_type(cert_type);
}

}  // namespace Botan::TLS
