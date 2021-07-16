/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_channel_impl_13.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/tls_messages.h>

namespace Botan {

namespace TLS {

Channel_Impl_13::Channel_Impl_13(Callbacks& callbacks,
                                 Session_Manager& session_manager,
                                 RandomNumberGenerator& rng,
                                 const Policy& policy,
                                 bool is_server,
                                 size_t reserved_io_buffer_size) :
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_rng(rng),
   m_policy(policy),
   m_is_server(is_server),
   m_has_been_closed(false)
   {
   /* epoch 0 is plaintext, thus null cipher state */
   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = nullptr;

   m_writebuf.reserve(reserved_io_buffer_size);
   m_readbuf.reserve(reserved_io_buffer_size);
   }

Channel_Impl_13::~Channel_Impl_13() = default;

size_t Channel_Impl_13::received_data(const uint8_t input[], size_t input_size)
   {
   try
      {
      while(input_size)
         {
         size_t consumed = 0;

         auto get_epoch = [this](uint16_t epoch) { return read_cipher_state_epoch(epoch); };

         const Record_Header record =
            read_record(false,
                        m_readbuf,
                        input,
                        input_size,
                        consumed,
                        m_record_buf,
                        m_sequence_numbers.get(),
                        get_epoch,
                        false);

         const size_t needed = record.needed();

         BOTAN_ASSERT(consumed > 0, "Got to eat something");

         BOTAN_ASSERT(consumed <= input_size,
                      "Record reader consumed sane amount");

         input += consumed;
         input_size -= consumed;

         BOTAN_ASSERT(input_size == 0 || needed == 0,
                      "Got a full record or consumed all input");

         if(input_size == 0 && needed != 0)
            return needed; // need more data to complete record

         if(m_record_buf.size() > MAX_PLAINTEXT_SIZE)
            throw TLS_Exception(Alert::RECORD_OVERFLOW,
                                "TLS plaintext record is larger than allowed maximum");

         const bool initial_record = !handshake_state();

         if(record.type() != ALERT)
            {
            if(initial_record)
               {
               // For initial records just check for basic sanity
               if(record.version().major_version() != 3 &&
                  record.version().major_version() != 0xFE)
                  {
                  throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                      "Received unexpected record version in initial record");
                  }
               }
            else if(auto state = handshake_state())
               {
               if(state->server_hello() != nullptr &&
                  record.version() != state->version())
                  {
                  if(record.version() != state->version())
                     {
                     throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                         "Received unexpected record version");
                     }
                  }
               }
            }

         if(record.type() == HANDSHAKE)
            {
            if(m_has_been_closed)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received handshake data after connection closure");

            //TODO: Handle the plain handshake message
            }
         else if (record.type() == CHANGE_CIPHER_SPEC)
            {
            if(m_has_been_closed)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received change cipher spec after connection closure");

            //TODO: Send CCS in response / middlebox compatibility mode to be defined via the policy
            }
         else if(record.type() == APPLICATION_DATA)
            {
            if(m_has_been_closed)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received application data after connection closure");

            if(initial_record)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Cannot handle plain application data");

            //TODO: Process application data or encrypted handshake messages
            }
         else if(record.type() == ALERT)
            {
            process_alert(m_record_buf);
            }
         else if(record.type() != NO_RECORD)
            throw Unexpected_Message("Unexpected record type " +
                                     std::to_string(record.type()) +
                                     " from counterparty");
         }

      return 0; // on a record boundary
      }
   catch(TLS_Exception& e)
      {
      send_fatal_alert(e.type());
      throw;
      }
   catch(Invalid_Authentication_Tag&)
      {
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

   return 0;
   }

void Channel_Impl_13::send(const uint8_t buf[], size_t buf_size)
   {
   BOTAN_UNUSED(buf, buf_size);

   return;
   }

void Channel_Impl_13::send_alert(const Alert& alert)
   {
   BOTAN_UNUSED(alert);
   }

bool Channel_Impl_13::is_active() const
   {
   return !is_closed();
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

Handshake_State& Channel_Impl_13::create_handshake_state(Protocol_Version version)
   {
   BOTAN_ASSERT(version == Botan::TLS::Protocol_Version::TLS_V13, "Have handshake version for TLS 1.3");

   if(handshake_state())
      throw Internal_Error("create_handshake_state called multiple times");

   if(!m_sequence_numbers)
      {
      m_sequence_numbers.reset(new Stream_Sequence_Numbers);
      }

   using namespace std::placeholders;

   std::unique_ptr<Handshake_IO> io = std::make_unique<Stream_Handshake_IO>(
     std::bind(&Channel_Impl_13::send_record, this, _1, _2));

   m_handshake_state = new_handshake_state(std::move(io));

   return *m_handshake_state.get();
   }


void Channel_Impl_13::write_record(Connection_Cipher_State* cipher_state, uint16_t epoch,
                                   uint8_t record_type, const uint8_t input[], size_t length)
   {
   BOTAN_ASSERT(handshake_state(), "Handshake state exists");

   const Protocol_Version record_version = handshake_state()->version();

   const uint64_t next_seq = sequence_numbers().next_write_sequence(epoch);

   if(cipher_state == nullptr)
      {
      TLS::write_unencrypted_record(m_writebuf, record_type, record_version, next_seq,
                                    input, length);
      }
   else
      {
      TLS::write_record(m_writebuf, record_type, record_version, next_seq,
                        input, length, *cipher_state, m_rng);
      }

   callbacks().tls_emit_data(m_writebuf.data(), m_writebuf.size());
   }

void Channel_Impl_13::send_record_array(uint16_t epoch, uint8_t type, const uint8_t input[], size_t length)
   {
   if(length == 0)
      return;

   auto cipher_state = write_cipher_state_epoch(epoch);

   while(length)
      {
      const size_t sending = std::min<size_t>(length, MAX_PLAINTEXT_SIZE);
      write_record(cipher_state.get(), epoch, type, input, sending);

      input += sending;
      length -= sending;
      }
   }

void Channel_Impl_13::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   send_record_array(sequence_numbers().current_write_epoch(),
                     record_type, record.data(), record.size());
   }

Connection_Sequence_Numbers& Channel_Impl_13::sequence_numbers() const
   {
   BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
   return *m_sequence_numbers;
   }

std::shared_ptr<Connection_Cipher_State> Channel_Impl_13::read_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_read_cipher_states.find(epoch);
   if(i == m_read_cipher_states.end())
      { throw Internal_Error("TLS::Channel_Impl_13 No read cipherstate for epoch " + std::to_string(epoch)); }
   return i->second;
   }

std::shared_ptr<Connection_Cipher_State> Channel_Impl_13::write_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_write_cipher_states.find(epoch);
   if(i == m_write_cipher_states.end())
      { throw Internal_Error("TLS::Channel_Impl_13 No write cipherstate for epoch " + std::to_string(epoch)); }
   return i->second;
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
       send_warning_alert(Alert::CLOSE_NOTIFY); // reply in kind

    if(alert_msg.type() == Alert::CLOSE_NOTIFY || alert_msg.is_fatal())
       {
       m_has_been_closed = true;
       }
    }

}

}
