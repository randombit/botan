/*
* TLS Channels
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_channel.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/assert.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

Channel::Channel(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                 std::tr1::function<void (const byte[], size_t, Alert)> proc_fn,
                 std::tr1::function<bool (const Session&)> handshake_complete) :
   proc_fn(proc_fn),
   handshake_fn(handshake_complete),
   writer(socket_output_fn),
   state(0),
   handshake_completed(false),
   connection_closed(false)
   {
   }

Channel::~Channel()
   {
   delete state;
   state = 0;
   }

size_t Channel::received_data(const byte buf[], size_t buf_size)
   {
   try
      {
      while(buf_size)
         {
         byte rec_type = CONNECTION_CLOSED;
         MemoryVector<byte> record;
         size_t consumed = 0;

         const size_t needed = reader.add_input(buf, buf_size,
                                                consumed,
                                                rec_type, record);

         buf += consumed;
         buf_size -= consumed;

         BOTAN_ASSERT(buf_size == 0 || needed == 0,
                      "Got a full record or consumed all input");

         if(buf_size == 0 && needed != 0)
            return needed; // need more data to complete record

         if(rec_type == APPLICATION_DATA)
            {
            if(handshake_completed)
               {
               /*
               * OpenSSL among others sends empty records in versions
               * before TLS v1.1 in order to randomize the IV of the
               * following record. Avoid spurious callbacks.
               */
               if(record.size() > 0)
                  proc_fn(&record[0], record.size(), Alert());
               }
            else
               {
               throw Unexpected_Message("Application data before handshake done");
               }
            }
         else if(rec_type == HANDSHAKE || rec_type == CHANGE_CIPHER_SPEC)
            {
            read_handshake(rec_type, record);
            }
         else if(rec_type == ALERT)
            {
            Alert alert_msg(record);

            alert_notify(alert_msg);

            proc_fn(0, 0, alert_msg);

            if(alert_msg.type() == Alert::CLOSE_NOTIFY)
               {
               if(connection_closed)
                  reader.reset();
               else
                  send_alert(Alert(Alert::CLOSE_NOTIFY)); // reply in kind
               }
            else if(alert_msg.is_fatal())
               {
               // delete state immediately
               connection_closed = true;

               delete state;
               state = 0;

               writer.reset();
               reader.reset();
               }
            }
         else
            throw Unexpected_Message("Unknown TLS message type " +
                                     to_string(rec_type) + " received");
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

/*
* Split up and process handshake messages
*/
void Channel::read_handshake(byte rec_type,
                             const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE)
      {
      if(!state)
         state = new Handshake_State(new Stream_Handshake_Reader);
      state->handshake_reader()->add_input(&rec_buf[0], rec_buf.size());
      }

   BOTAN_ASSERT(state, "Handshake message recieved without state in place");

   while(true)
      {
      Handshake_Type type = HANDSHAKE_NONE;

      if(rec_type == HANDSHAKE)
         {
         if(state->handshake_reader()->have_full_record())
            {
            std::pair<Handshake_Type, MemoryVector<byte> > msg =
               state->handshake_reader()->get_next_record();
            process_handshake_msg(msg.first, msg.second);
            }
         else
            break;
         }
      else if(rec_type == CHANGE_CIPHER_SPEC)
         {
         if(state->handshake_reader()->empty() && rec_buf.size() == 1 && rec_buf[0] == 1)
            process_handshake_msg(HANDSHAKE_CCS, MemoryVector<byte>());
         else
            throw Decoding_Error("Malformed ChangeCipherSpec message");
         }
      else
         throw Decoding_Error("Unknown message type in handshake processing");

      if(type == HANDSHAKE_CCS || !state || !state->handshake_reader()->have_full_record())
         break;
      }
   }

void Channel::send(const byte buf[], size_t buf_size)
   {
   if(!is_active())
      throw std::runtime_error("Data cannot be sent on inactive TLS connection");

   writer.send(APPLICATION_DATA, buf, buf_size);
   }

void Channel::send_alert(const Alert& alert)
   {
   if(alert.is_valid() && !connection_closed)
      {
      try
         {
         writer.send_alert(alert);
         }
      catch(...) { /* swallow it */ }
      }

   if(!connection_closed && (alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal()))
      {
      connection_closed = true;

      delete state;
      state = 0;

      writer.reset();
      }
   }

void Channel::Secure_Renegotiation_State::update(Client_Hello* client_hello)
   {
   if(initial_handshake)
      {
      secure_renegotiation = client_hello->secure_renegotiation();
      }
   else
      {
      if(secure_renegotiation != client_hello->secure_renegotiation())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client changed its mind about secure renegotiation");
      }

   if(client_hello->secure_renegotiation())
      {
      const MemoryVector<byte>& data = client_hello->renegotiation_info();

      if(initial_handshake)
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

void Channel::Secure_Renegotiation_State::update(Server_Hello* server_hello)
   {
   if(initial_handshake)
      {
      /* If the client offered but server rejected, then this toggles
      *  secure_renegotiation to off
      */
      secure_renegotiation = server_hello->secure_renegotiation();
      }
   else
      {
      if(secure_renegotiation != server_hello->secure_renegotiation())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server changed its mind about secure renegotiation");
      }

   if(secure_renegotiation)
      {
      const MemoryVector<byte>& data = server_hello->renegotiation_info();

      if(initial_handshake)
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

   initial_handshake = false;
   }

void Channel::Secure_Renegotiation_State::update(Finished* client_finished,
                                                     Finished* server_finished)
   {
   client_verify = client_finished->verify_data();
   server_verify = server_finished->verify_data();
   }

}

}
