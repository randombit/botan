/*
* TLS Channels
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_channel.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_heartbeats.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/assert.h>
#include <botan/internal/rounding.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

Channel::Channel(std::function<void (const byte[], size_t)> output_fn,
                 std::function<void (const byte[], size_t, Alert)> proc_fn,
                 std::function<bool (const Session&)> handshake_complete,
                 Session_Manager& session_manager,
                 RandomNumberGenerator& rng) :
   m_handshake_fn(handshake_complete),
   m_rng(rng),
   m_session_manager(session_manager),
   m_proc_fn(proc_fn),
   m_output_fn(output_fn),
   m_writebuf(TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE),
   m_readbuf(TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE)
   {
   }

Channel::~Channel()
   {
   // So unique_ptr destructors run correctly
   }

Handshake_State& Channel::create_handshake_state()
   {
   if(m_state)
      throw Internal_Error("create_handshake_state called during handshake");

   m_state.reset(new_handshake_state());

   return *m_state.get();
   }

void Channel::renegotiate(bool force_full_renegotiation)
   {
   if(m_state) // currently in handshake?
      return;

   m_state.reset(new_handshake_state());

   initiate_handshake(*m_state.get(), force_full_renegotiation);
   }

void Channel::set_protocol_version(Protocol_Version version)
   {
   m_current_version = version;
   m_state->set_version(version);
   }

void Channel::set_maximum_fragment_size(size_t max_fragment)
   {
   if(max_fragment == 0)
      m_max_fragment = MAX_PLAINTEXT_SIZE;
   else
      m_max_fragment = clamp(max_fragment, 128, MAX_PLAINTEXT_SIZE);
   }

void Channel::change_cipher_spec_reader(Connection_Side side)
   {
   if(m_state->server_hello()->compression_method()!= NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

   m_read_seq_no = 0;

   // flip side as we are reading
   side = (side == CLIENT) ? SERVER : CLIENT;

   m_read_cipherstate.reset(
      new Connection_Cipher_State(current_protocol_version(),
                                  side,
                                  m_state->ciphersuite(),
                                  m_state->session_keys())
      );
   }

void Channel::change_cipher_spec_writer(Connection_Side side)
   {
   if(m_state->server_hello()->compression_method()!= NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

   /*
   RFC 4346:
     A sequence number is incremented after each record: specifically,
     the first record transmitted under a particular connection state
     MUST use sequence number 0
   */
   m_write_seq_no = 0;

   m_write_cipherstate.reset(
      new Connection_Cipher_State(current_protocol_version(),
                                  side,
                                  m_state->ciphersuite(),
                                  m_state->session_keys())
      );
   }

void Channel::activate_session(const std::vector<byte>& session_id)
   {
   m_secure_renegotiation.update(m_state->client_finished(),
                                 m_state->server_finished());

   m_state.reset();
   m_handshake_completed = true;
   m_active_session = session_id;
   }

void Channel::heartbeat_support(bool peer_supports, bool sending_allowed)
   {
   m_peer_supports_heartbeats = peer_supports;
   m_heartbeat_sending_allowed = sending_allowed;
   }

size_t Channel::received_data(const byte buf[], size_t buf_size)
   {
   try
      {
      while(buf_size)
         {
         byte rec_type = CONNECTION_CLOSED;
         std::vector<byte> record;
         u64bit record_number = 0;

         size_t consumed = 0;

         const size_t needed = TLS::read_record(m_readbuf,
                                                m_readbuf_pos,
                                                buf,
                                                buf_size,
                                                consumed,
                                                rec_type,
                                                record,
                                                m_read_seq_no,
                                                m_current_version,
                                                m_read_cipherstate.get());

         if(needed == 0) // full message decoded
            {
            if(record.size() > m_max_fragment)
               throw TLS_Exception(Alert::RECORD_OVERFLOW,
                                   "Plaintext record is too large");

            record_number = m_read_seq_no;
            m_read_seq_no += 1;
            }

         BOTAN_ASSERT(consumed <= buf_size,
                      "Record reader consumed sane amount");

         buf += consumed;
         buf_size -= consumed;

         BOTAN_ASSERT(buf_size == 0 || needed == 0,
                      "Got a full record or consumed all input");

         if(buf_size == 0 && needed != 0)
            return needed; // need more data to complete record

         if(rec_type == HANDSHAKE || rec_type == CHANGE_CIPHER_SPEC)
            {
            if(!m_state)
               m_state.reset(new_handshake_state());

            m_state->handshake_io().add_input(rec_type,
                                              &record[0],
                                              record.size(),
                                              record_number);

            while(m_state)
               {
               auto msg = m_state->get_next_handshake_msg();

               if(msg.first == HANDSHAKE_NONE) // no full handshake yet
                  break;

               process_handshake_msg(*m_state.get(), msg.first, msg.second);
               }
            }
         else if(rec_type == HEARTBEAT && m_peer_supports_heartbeats)
            {
            Heartbeat_Message heartbeat(record);

            const std::vector<byte>& payload = heartbeat.payload();

            if(heartbeat.is_request())
               {
               if(!m_state) // no heartbeats during handshake
                  {
                  Heartbeat_Message response(Heartbeat_Message::RESPONSE,
                                             &payload[0], payload.size());

                  send_record(HEARTBEAT, response.contents());
                  }
               }
            else
               {
               // a response, pass up to the application
               m_proc_fn(&payload[0], payload.size(), Alert(Alert::HEARTBEAT_PAYLOAD));
               }
            }
         else if(rec_type == APPLICATION_DATA)
            {
            if(m_handshake_completed)
               {
               /*
               * OpenSSL among others sends empty records in versions
               * before TLS v1.1 in order to randomize the IV of the
               * following record. Avoid spurious callbacks.
               */
               if(record.size() > 0)
                  m_proc_fn(&record[0], record.size(), Alert());
               }
            else
               {
               throw Unexpected_Message("Application data before handshake done");
               }
            }
         else if(rec_type == ALERT)
            {
            Alert alert_msg(record);

            if(alert_msg.type() == Alert::NO_RENEGOTIATION)
               {
               if(m_handshake_completed && m_state)
                  m_state.reset();
               }

            m_proc_fn(nullptr, 0, alert_msg);

            if(alert_msg.type() == Alert::CLOSE_NOTIFY)
               {
               if(m_connection_closed)
                  m_read_cipherstate.reset();
               else
                  send_alert(Alert(Alert::CLOSE_NOTIFY)); // reply in kind
               }
            else if(alert_msg.is_fatal())
               {
               // delete state immediately

               if(!m_active_session.empty())
                  {
                  m_session_manager.remove_entry(m_active_session);
                  m_active_session.clear();
                  }

               m_connection_closed = true;

               m_state.reset();

               m_write_cipherstate.reset();
               m_read_cipherstate.reset();
               }
            }
         else
            throw Unexpected_Message("Unknown TLS message type " +
                                     std::to_string(rec_type) + " received");
         }

      return 0; // on a record boundary
      }
   catch(TLS_Exception& e)
      {
      send_alert(Alert(e.type(), true));
      throw;
      }
   catch(Decoding_Error& e)
      {
      send_alert(Alert(Alert::DECODE_ERROR, true));
      throw;
      }
   catch(Internal_Error& e)
      {
      send_alert(Alert(Alert::INTERNAL_ERROR, true));
      throw;
      }
   catch(std::exception& e)
      {
      send_alert(Alert(Alert::INTERNAL_ERROR, true));
      throw;
      }
   }

void Channel::heartbeat(const byte payload[], size_t payload_size)
   {
   if(!is_active())
      throw std::runtime_error("Heartbeat cannot be sent on inactive TLS connection");

   if(m_heartbeat_sending_allowed)
      {
      Heartbeat_Message heartbeat(Heartbeat_Message::REQUEST,
                                  payload, payload_size);

      send_record(HEARTBEAT, heartbeat.contents());
      }
   }

void Channel::send_record(byte type, const byte input[], size_t length)
   {
   if(length == 0)
      return;

   /*
   * If using CBC mode in SSLv3/TLS v1.0, send a single byte of
   * plaintext to randomize the (implicit) IV of the following main
   * block. If using a stream cipher, or TLS v1.1 or higher, this
   * isn't necessary.
   *
   * An empty record also works but apparently some implementations do
   * not like this (https://bugzilla.mozilla.org/show_bug.cgi?id=665814)
   *
   * See http://www.openssl.org/~bodo/tls-cbc.txt for background.
   */
   if((type == APPLICATION_DATA) &&
      (m_write_cipherstate->block_size() > 0) &&
      (m_write_cipherstate->iv_size() == 0))
      {
      write_record(type, &input[0], 1);
      input += 1;
      length -= 1;
      }

   while(length)
      {
      const size_t sending = std::min(length, m_max_fragment);
      write_record(type, &input[0], sending);

      input += sending;
      length -= sending;
      }
   }

void Channel::send_record(byte record_type, const std::vector<byte>& record)
   {
   send_record(record_type, &record[0], record.size());
   }

void Channel::write_record(byte record_type, const byte input[], size_t length)
   {
   if(length > m_max_fragment)
      throw Internal_Error("Record is larger than allowed fragment size");

   Protocol_Version record_version = current_protocol_version();
   if(!record_version.valid())
      {
      BOTAN_ASSERT(m_state && !m_state->server_hello(),
                   "In first record of client connection");

      record_version = m_state->handshake_io().initial_record_version();
      }

   TLS::write_record(m_writebuf,
                     record_type,
                     input,
                     length,
                     m_write_seq_no,
                     record_version,
                     m_write_cipherstate.get(),
                     m_rng);

   m_write_seq_no += 1;
   m_output_fn(&m_writebuf[0], m_writebuf.size());
   }

void Channel::send(const byte buf[], size_t buf_size)
   {
   if(!is_active())
      throw std::runtime_error("Data cannot be sent on inactive TLS connection");

   send_record(APPLICATION_DATA, buf, buf_size);
   }

void Channel::send(const std::string& string)
   {
   this->send(reinterpret_cast<const byte*>(string.c_str()), string.size());
   }

void Channel::send_alert(const Alert& alert)
   {
   if(alert.is_valid() && !m_connection_closed)
      {
      try
         {
         send_record(ALERT, alert.serialize());
         }
      catch(...) { /* swallow it */ }
      }

   if(alert.type() == Alert::NO_RENEGOTIATION)
      m_state.reset();

   if(alert.is_fatal() && !m_active_session.empty())
      {
      m_session_manager.remove_entry(m_active_session);
      m_active_session.clear();
      }

   if(!m_connection_closed && (alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal()))
      {
      m_connection_closed = true;

      m_state.reset();
      m_write_cipherstate.reset();
      }
   }

void Channel::Secure_Renegotiation_State::update(const Client_Hello* client_hello)
   {
   if(initial_handshake())
      {
      m_secure_renegotiation = client_hello->secure_renegotiation();
      }
   else
      {
      if(supported() && !client_hello->secure_renegotiation())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client changed its mind about secure renegotiation");
      }

   if(client_hello->secure_renegotiation())
      {
      const std::vector<byte>& data = client_hello->renegotiation_info();

      if(initial_handshake())
         {
         if(!data.empty())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Client sent renegotiation data on initial handshake");
         }
      else
         {
         if(data != for_client_hello())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Client sent bad renegotiation data");
         }
      }
   }

void Channel::Secure_Renegotiation_State::update(const Server_Hello* server_hello)
   {
   if(initial_handshake())
      {
      /* If the client offered but server rejected, then this toggles
      *  secure_renegotiation to off
      */
      if(m_secure_renegotiation)
         m_secure_renegotiation = server_hello->secure_renegotiation();
      }
   else
      {
      if(supported() != server_hello->secure_renegotiation())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server changed its mind about secure renegotiation");
      }

   if(supported())
      {
      const std::vector<byte>& data = server_hello->renegotiation_info();

      if(initial_handshake())
         {
         if(!data.empty())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent renegotiation data on initial handshake");
         }
      else
         {
         if(data != for_server_hello())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Server sent bad renegotiation data");
         }
      }

   m_initial_handshake = false;
   }

void Channel::Secure_Renegotiation_State::update(const Finished* client_finished,
                                                 const Finished* server_finished)
   {
   m_client_verify = client_finished->verify_data();
   m_server_verify = server_finished->verify_data();
   }

}

}

