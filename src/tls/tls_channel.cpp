/*
* TLS Channels
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_channel.h>
#include <botan/internal/tls_alerts.h>
#include <botan/internal/tls_state.h>
#include <botan/loadstor.h>

#include <stdio.h>

namespace Botan {

TLS_Channel::TLS_Channel(std::tr1::function<void (const byte[], size_t)> socket_output_fn,
                         std::tr1::function<void (const byte[], size_t, u16bit)> proc_fn) :
   proc_fn(proc_fn),
   writer(socket_output_fn),
   state(0),
   active(false)
   {
   }

TLS_Channel::~TLS_Channel()
   {
   close();
   delete state;
   state = 0;
   }

size_t TLS_Channel::received_data(const byte buf[], size_t buf_size)
   {
   try
      {
      reader.add_input(buf, buf_size);

      byte rec_type = CONNECTION_CLOSED;
      SecureVector<byte> record;

      while(!reader.currently_empty())
         {
         const size_t bytes_needed = reader.get_record(rec_type, record);

         if(bytes_needed > 0)
            return bytes_needed;

         if(rec_type == APPLICATION_DATA)
            {
            if(active)
               {
               /*
               * OpenSSL among others sends empty records in versions
               * before TLS v1.1 in order to randomize the IV of the
               * following record. Avoid spurious callbacks.
               */
               if(record.size() > 0)
                  proc_fn(&record[0], record.size(), NULL_ALERT);
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

            proc_fn(0, 0, alert_msg.type());

            if(alert_msg.is_fatal() || alert_msg.type() == CLOSE_NOTIFY)
               {
               if(alert_msg.type() == CLOSE_NOTIFY)
                  alert(FATAL, CLOSE_NOTIFY);
               else
                  alert(FATAL, NULL_ALERT);
               }
            }
         else
            throw Unexpected_Message("Unknown message type received");
         }

      return 0; // on a record boundary
      }
   catch(TLS_Exception& e)
      {
      alert(FATAL, e.type());
      throw;
      }
   catch(Decoding_Error& e)
      {
      alert(FATAL, DECODE_ERROR);
      throw;
      }
   catch(std::exception& e)
      {
      alert(FATAL, INTERNAL_ERROR);
      throw;
      }
   }

/*
* Split up and process handshake messages
*/
void TLS_Channel::read_handshake(byte rec_type,
                                 const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE)
      {
      if(!state)
         state = new Handshake_State;
      state->queue.write(&rec_buf[0], rec_buf.size());
      }

   while(true)
      {
      Handshake_Type type = HANDSHAKE_NONE;
      SecureVector<byte> contents;

      if(rec_type == HANDSHAKE)
         {
         if(state->queue.size() >= 4)
            {
            byte head[4] = { 0 };
            state->queue.peek(head, 4);

            const size_t length = make_u32bit(0, head[1], head[2], head[3]);

            if(state->queue.size() >= length + 4)
               {
               type = static_cast<Handshake_Type>(head[0]);
               contents.resize(length);
               state->queue.read(head, 4);
               state->queue.read(&contents[0], contents.size());
               }
            }
         }
      else if(rec_type == CHANGE_CIPHER_SPEC)
         {
         if(state->queue.size() == 0 && rec_buf.size() == 1 && rec_buf[0] == 1)
            type = HANDSHAKE_CCS;
         else
            throw Decoding_Error("Malformed ChangeCipherSpec message");
         }
      else
         throw Decoding_Error("Unknown message type in handshake processing");

      if(type == HANDSHAKE_NONE)
         break;

      process_handshake_msg(type, contents);

      if(type == HANDSHAKE_CCS || !state)
         break;
      }
   }

void TLS_Channel::queue_for_sending(const byte buf[], size_t buf_size)
   {
   if(active)
      {
      while(!pre_handshake_write_queue.end_of_data())
         {
         SecureVector<byte> q_buf(1024);
         const size_t got = pre_handshake_write_queue.read(&q_buf[0], q_buf.size());
         writer.send(APPLICATION_DATA, &q_buf[0], got);
         }

      writer.send(APPLICATION_DATA, buf, buf_size);
      }
   else
      pre_handshake_write_queue.write(buf, buf_size);
   }

void TLS_Channel::alert(Alert_Level alert_level, Alert_Type alert_code)
   {
   if(alert_code != NULL_ALERT)
      {
      try
         {
         writer.alert(alert_level, alert_code);
         }
      catch(...) { /* swallow it */ }
      }

   if(active && alert_level == FATAL)
      {
      reader.reset();
      writer.reset();
      delete state;
      state = 0;
      active = false;
      }
   }

void TLS_Channel::Secure_Renegotiation_State::update(Client_Hello* client_hello)
   {

   }

void TLS_Channel::Secure_Renegotiation_State::update(Server_Hello* server_hello)
   {
   secure_renegotiation = server_hello->secure_renegotiation();

   printf("server hello says sec reneg: %d\n", secure_renegotiation);

   if(secure_renegotiation)
      {
      const MemoryVector<byte>& data = server_hello->renegotiation_info();

      if(initial_handshake)
         {
         if(!data.empty())
            throw TLS_Exception(HANDSHAKE_FAILURE,
                                "Server sent renegotiation data on initial handshake");
         }
      else
         {
         if(data != for_server_hello())
            throw TLS_Exception(HANDSHAKE_FAILURE,
                                "Server sent bad renegotiation data");
         }
      }

   initial_handshake = false;
   }

void TLS_Channel::Secure_Renegotiation_State::update(Finished* client_finished,
                                                     Finished* server_finished)
   {
   client_verify = client_finished->verify_data();
   server_verify = server_finished->verify_data();
   }

}
