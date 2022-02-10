/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>

#include <botan/hash.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/tls_messages.h>

namespace Botan {

namespace TLS {

Channel_Impl_13::Channel_Impl_13(Callbacks& callbacks,
                                 Session_Manager& session_manager,
                                 RandomNumberGenerator& rng,
                                 const Policy& policy,
                                 bool is_server,
                                 size_t reserved_io_buffer_size) :
   m_side(is_server ? Connection_Side::SERVER : Connection_Side::CLIENT),
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_rng(rng),
   m_policy(policy),
   m_record_layer(m_side),
   m_handshake_layer(m_side),
   m_has_been_closed(false)
   {
   m_writebuf.reserve(reserved_io_buffer_size);
   m_readbuf.reserve(reserved_io_buffer_size);
   }

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::received_data(const uint8_t input[], size_t input_size)
   {
   try
      {
      m_record_layer.copy_data(std::vector(input, input+input_size));

      while(true)
         {
         auto result = m_record_layer.next_record(m_cipher_state.get());

         if(std::holds_alternative<BytesNeeded>(result))
            {
            return std::get<BytesNeeded>(result);
            }

         auto record = std::get<Record>(result);

         if(record.type == HANDSHAKE)
            {
            if(m_has_been_closed)
               { throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received handshake data after connection closure"); }

            m_handshake_layer.copy_data(unlock(record.fragment));  // TODO: record fragment should be an ordinary std::vector

            // m_handshake_state->handshake_io().add_record(record.fragment.data(),
            //       record.fragment.size(),
            //       record.type,
            //       0 /* sequence number unused in TLS 1.3 */);

            while (true)
               {
               // TODO: BytesNeeded is not needed here, hence we could make `next_message` return an optional
               auto handshake_msg = m_handshake_layer.next_message(policy(), m_transcript_hash);

               if(std::holds_alternative<BytesNeeded>(handshake_msg))
                  {
                  break;
                  }

               process_handshake_msg(std::move(std::get<Handshake_Message_13>(handshake_msg)));
               }

//            while(true)
//               {
//               auto [type, content] = m_handshake_state->get_next_handshake_msg();
//               if(type == HANDSHAKE_NONE)
//                  {
//                  break;
//                  }
//               else if (type == NEW_SESSION_TICKET || type == KEY_UPDATE /* TODO or POST_HANDSHAKE_AUTH */)
//                  {
//                  process_post_handshake_msg(*m_handshake_state.get(), type, content);
//                  }
//               else
//                  {
//                  process_handshake_msg(*m_handshake_state.get(), type, content);
//                  }
//               }
            }
         else if(record.type == CHANGE_CIPHER_SPEC)
            {
            if(m_has_been_closed)
               { throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received change cipher spec after connection closure"); }

            // TODO: Send CCS in response / middlebox compatibility mode to be defined via the policy
            // TODO: as described in RFC 8446 Sec 5
            }
         else if(record.type == APPLICATION_DATA)
            {
            if(m_has_been_closed)
               { throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received application data after connection closure"); }

            BOTAN_ASSERT(record.seq_no.has_value(), "decrypted application traffic had a sequence number");
            callbacks().tls_record_received(record.seq_no.value(), record.fragment.data(), record.fragment.size());
            }
         else if(record.type == ALERT)
            {
            process_alert(record.fragment);
            }
         else if(record.type != NO_RECORD)
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
   send_record(Record_Type::HANDSHAKE, m_handshake_layer.prepare_message(message, m_transcript_hash));
   }

void Channel_Impl_13::send(const uint8_t buf[], size_t buf_size)
   {
   if(!is_active())
      { throw Invalid_State("Data cannot be sent on inactive TLS connection"); }

   send_record(Record_Type::APPLICATION_DATA, {buf, buf+buf_size});
   }

// void Channel_Impl_13::send_handshake_message(Handshake_Message_13& )
//    {
//    m_handshake_layer.prepare_message(hello);
//    }

void Channel_Impl_13::send_alert(const Alert& alert)
   {
   if(alert.is_valid() && !is_closed())
      {
      try
         {
         send_record(Record_Type::ALERT, alert.serialize());
         }
      catch(...) { /* swallow it */ }
      }

   // TODO handle alerts
   }

bool Channel_Impl_13::is_active() const
   {
   return !is_closed() && m_cipher_state != nullptr && m_cipher_state->ready_for_application_traffic();
   }

bool Channel_Impl_13::is_closed() const
   {
   return m_has_been_closed;
   }

std::vector<X509_Certificate> Channel_Impl_13::peer_cert_chain() const
   {
   return std::vector<X509_Certificate>();
   }

SymmetricKey Channel_Impl_13::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   BOTAN_UNUSED(label, context, length);

   return SymmetricKey();
   }

void Channel_Impl_13::renegotiate(bool force_full_renegotiation)
   {
   BOTAN_UNUSED(force_full_renegotiation);

   throw Botan::TLS::Unexpected_Message("Cannot renegotiate in TLS 1.3");
   }

bool Channel_Impl_13::secure_renegotiation_supported() const
   {
   // No renegotiation supported in TLS 1.3
   return false;
   }

bool Channel_Impl_13::timeout_check()
   {
   return false;
   }

void Channel_Impl_13::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   const auto to_write = m_record_layer.prepare_records(static_cast<Record_Type>(record_type),
                         record, m_cipher_state.get());
   callbacks().tls_emit_data(to_write.data(), to_write.size());
   }

Connection_Sequence_Numbers& Channel_Impl_13::sequence_numbers() const
   {
   BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
   return *m_sequence_numbers;
   }

void Channel_Impl_13::process_alert(const secure_vector<uint8_t>& record)
   {
   Alert alert_msg(record);

   callbacks().tls_alert(alert_msg);

   if(alert_msg.is_fatal())
      {
      //TODO: single handshake state should have some flag to indicate, whether it is active?
      //  if(auto state = handshake_state())
      //     m_session_manager.remove_entry(state->server_hello()->session_id());
      }

   if(alert_msg.type() == Alert::CLOSE_NOTIFY)
      { send_warning_alert(Alert::CLOSE_NOTIFY); } // reply in kind

   if(alert_msg.type() == Alert::CLOSE_NOTIFY || alert_msg.is_fatal())
      {
      m_has_been_closed = true;
      }
   }

}

}
