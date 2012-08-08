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
#include <botan/internal/assert.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

Channel::Channel(std::function<void (const byte[], size_t)> socket_output_fn,
                 std::function<void (const byte[], size_t, Alert)> proc_fn,
                 std::function<bool (const Session&)> handshake_complete,
                 Session_Manager& session_manager,
                 RandomNumberGenerator& rng) :
   m_proc_fn(proc_fn),
   m_handshake_fn(handshake_complete),
   m_state(nullptr),
   m_session_manager(session_manager),
   m_writer(socket_output_fn, rng),
   m_handshake_completed(false),
   m_connection_closed(false),
   m_peer_supports_heartbeats(false),
   m_heartbeat_sending_allowed(false)
   {
   }

Channel::~Channel()
   {
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

         const size_t needed = m_reader.add_input(buf, buf_size,
                                                  consumed,
                                                  rec_type,
                                                  record,
                                                  record_number);

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

               process_handshake_msg(msg.first, msg.second);
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

                  m_writer.send(HEARTBEAT, response.contents());
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

            alert_notify(alert_msg);

            m_proc_fn(nullptr, 0, alert_msg);

            if(alert_msg.type() == Alert::CLOSE_NOTIFY)
               {
               if(m_connection_closed)
                  m_reader.reset();
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

               m_writer.reset();
               m_reader.reset();
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

      m_writer.send(HEARTBEAT, heartbeat.contents());
      }
   }

void Channel::send(const byte buf[], size_t buf_size)
   {
   if(!is_active())
      throw std::runtime_error("Data cannot be sent on inactive TLS connection");

   m_writer.send(APPLICATION_DATA, buf, buf_size);
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
         m_writer.send_alert(alert);
         }
      catch(...) { /* swallow it */ }
      }

   if(alert.is_fatal() && !m_active_session.empty())
      {
      m_session_manager.remove_entry(m_active_session);
      m_active_session.clear();
      }

   if(!m_connection_closed && (alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal()))
      {
      m_connection_closed = true;

      m_state.reset();
      m_writer.reset();
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

