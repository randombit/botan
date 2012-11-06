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
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/assert.h>
#include <botan/internal/rounding.h>
#include <botan/internal/stl_util.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

Channel::Channel(std::function<void (const byte[], size_t)> output_fn,
                 std::function<void (const byte[], size_t, Alert)> proc_fn,
                 std::function<bool (const Session&)> handshake_complete,
                 Session_Manager& session_manager,
                 RandomNumberGenerator& rng) :
   m_handshake_fn(handshake_complete),
   m_proc_fn(proc_fn),
   m_output_fn(output_fn),
   m_rng(rng),
   m_session_manager(session_manager)
   {
   }

Channel::~Channel()
   {
   // So unique_ptr destructors run correctly
   }

Connection_Sequence_Numbers& Channel::sequence_numbers() const
   {
   BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
   return *m_sequence_numbers;
   }

std::shared_ptr<Connection_Cipher_State> Channel::read_cipher_state_epoch(u16bit epoch) const
   {
   auto i = m_read_cipher_states.find(epoch);

   BOTAN_ASSERT(i != m_read_cipher_states.end(),
                "Have a cipher state for the specified epoch");

   return i->second;
   }

std::shared_ptr<Connection_Cipher_State> Channel::write_cipher_state_epoch(u16bit epoch) const
   {
   auto i = m_write_cipher_states.find(epoch);

   BOTAN_ASSERT(i != m_write_cipher_states.end(),
                "Have a cipher state for the specified epoch");

   return i->second;
   }

std::shared_ptr<Connection_Cipher_State> Channel::read_cipher_state_current() const
   {
   return read_cipher_state_epoch(sequence_numbers().current_read_epoch());
   }

std::shared_ptr<Connection_Cipher_State> Channel::write_cipher_state_current() const
   {
   return write_cipher_state_epoch(sequence_numbers().current_write_epoch());
   }

std::vector<X509_Certificate> Channel::peer_cert_chain() const
   {
   if(auto active = active_state())
      return get_peer_cert_chain(*active);
   return std::vector<X509_Certificate>();
   }

Handshake_State& Channel::create_handshake_state(Protocol_Version version)
   {
   const size_t dtls_mtu = 1400; // fixme should be settable

   if(pending_state())
      throw Internal_Error("create_handshake_state called during handshake");

   if(auto active = active_state())
      {
      Protocol_Version active_version = active->version();

      if(active_version.is_datagram_protocol() != version.is_datagram_protocol())
         throw std::runtime_error("Active state using version " +
                                  active_version.to_string() +
                                  " cannot change to " +
                                  version.to_string() +
                                  " in pending");
      }

   if(!m_sequence_numbers)
      {
      if(version.is_datagram_protocol())
         m_sequence_numbers.reset(new Datagram_Sequence_Numbers);
      else
         m_sequence_numbers.reset(new Stream_Sequence_Numbers);
      }

   auto send_rec = std::bind(&Channel::send_record, this,
                             std::placeholders::_1,
                             std::placeholders::_2);

   std::unique_ptr<Handshake_IO> io;
   if(version.is_datagram_protocol())
      io.reset(new Datagram_Handshake_IO(send_rec, dtls_mtu));
   else
      io.reset(new Stream_Handshake_IO(send_rec));

   m_pending_state.reset(new_handshake_state(io.release()));

   if(auto active = active_state())
      m_pending_state->set_version(active->version());

   return *m_pending_state.get();
   }

void Channel::renegotiate(bool force_full_renegotiation)
   {
   if(pending_state()) // currently in handshake?
      return;

   if(auto active = active_state())
      initiate_handshake(create_handshake_state(active->version()),
                         force_full_renegotiation);
   else
      throw std::runtime_error("Cannot renegotiate on inactive connection");
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
   auto pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(),
                "Have received server hello");

   if(pending->server_hello()->compression_method() != NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

   sequence_numbers().new_read_cipher_state();

   const u16bit epoch = sequence_numbers().current_read_epoch();

   BOTAN_ASSERT(m_read_cipher_states.count(epoch) == 0,
                "No read cipher state currently set for next epoch");

   // flip side as we are reading
   std::shared_ptr<Connection_Cipher_State> read_state(
      new Connection_Cipher_State(pending->version(),
                                  (side == CLIENT) ? SERVER : CLIENT,
                                  pending->ciphersuite(),
                                  pending->session_keys()));

   m_read_cipher_states[epoch] = read_state;
   }

void Channel::change_cipher_spec_writer(Connection_Side side)
   {
   auto pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(),
                "Have received server hello");

   if(pending->server_hello()->compression_method() != NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

   sequence_numbers().new_write_cipher_state();

   const u16bit epoch = sequence_numbers().current_write_epoch();

   BOTAN_ASSERT(m_write_cipher_states.count(epoch) == 0,
                "No write cipher state currently set for next epoch");

   std::shared_ptr<Connection_Cipher_State> write_state(
      new Connection_Cipher_State(pending->version(),
                                  side,
                                  pending->ciphersuite(),
                                  pending->session_keys()));

   m_write_cipher_states[epoch] = write_state;
   }

bool Channel::is_active() const
   {
   return (active_state() != nullptr);
   }

bool Channel::is_closed() const
   {
   return m_connection_closed;
   }

void Channel::activate_session()
   {
   std::swap(m_active_state, m_pending_state);
   m_pending_state.reset();

   const u16bit last_valid_epoch = get_last_valid_epoch();

   const auto obsolete_epoch =
      [last_valid_epoch](u16bit epoch) { return (epoch < last_valid_epoch); };

   map_remove_if(obsolete_epoch, m_write_cipher_states);
   map_remove_if(obsolete_epoch, m_read_cipher_states);
   }

u16bit Channel::get_last_valid_epoch() const
   {
   if(m_active_state->version().is_datagram_protocol())
      {
      // DTLS: find first epoch less than TCP MSL

      // FIXME: what about lost/retransmitted flights?
      const std::chrono::seconds tcp_msl(120);

      for(auto i : m_read_cipher_states)
         {
         if(i.second->age() <= tcp_msl)
            return i.first;

         if(i.first == sequence_numbers().current_read_epoch())
            return i.first;
         }

      throw std::logic_error("Could not find current DTLS epoch");
      }
   else
      {
      // TLS is easy case
      return sequence_numbers().current_write_epoch();
      }
   }

bool Channel::peer_supports_heartbeats() const
   {
   if(auto active = active_state())
      return active->server_hello()->supports_heartbeats();
   return false;
   }

bool Channel::heartbeat_sending_allowed() const
   {
   if(auto active = active_state())
      return active->server_hello()->peer_can_send_heartbeats();
   return false;
   }

size_t Channel::received_data(const byte buf[], size_t buf_size)
   {
   try
      {
      while(!is_closed() && buf_size)
         {
         byte rec_type = NO_RECORD;
         std::vector<byte> record;
         u64bit record_sequence = 0;
         Protocol_Version record_version;

         size_t consumed = 0;

         auto cipher_state = read_cipher_state_current();

         const size_t needed =
            read_record(m_readbuf,
                        buf,
                        buf_size,
                        consumed,
                        rec_type,
                        record,
                        record_version,
                        record_sequence,
                        m_sequence_numbers.get(),
                        cipher_state.get());

         BOTAN_ASSERT(consumed <= buf_size,
                      "Record reader consumed sane amount");

         buf += consumed;
         buf_size -= consumed;

         BOTAN_ASSERT(buf_size == 0 || needed == 0,
                      "Got a full record or consumed all input");

         if(buf_size == 0 && needed != 0)
            return needed; // need more data to complete record

         if(rec_type == NO_RECORD)
            continue;

         if(record.size() > m_max_fragment)
            throw TLS_Exception(Alert::RECORD_OVERFLOW,
                                "Plaintext record is too large");

         if(rec_type == HANDSHAKE || rec_type == CHANGE_CIPHER_SPEC)
            {
            if(!m_pending_state)
               {
               create_handshake_state(record_version);
               if(record_version.is_datagram_protocol())
                  sequence_numbers().read_accept(record_sequence);
               }

            m_pending_state->handshake_io().add_input(
               rec_type, &record[0], record.size(), record_sequence);

            while(auto pending = m_pending_state.get())
               {
               auto msg = pending->get_next_handshake_msg();

               if(msg.first == HANDSHAKE_NONE) // no full handshake yet
                  break;

               process_handshake_msg(active_state(), *pending,
                                     msg.first, msg.second);
               }
            }
         else if(rec_type == HEARTBEAT && peer_supports_heartbeats())
            {
            if(!active_state())
               throw Unexpected_Message("Heartbeat sent before handshake done");

            Heartbeat_Message heartbeat(record);

            const std::vector<byte>& payload = heartbeat.payload();

            if(heartbeat.is_request())
               {
               if(!pending_state())
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
            if(!active_state())
               throw Unexpected_Message("Application data before handshake done");

            /*
            * OpenSSL among others sends empty records in versions
            * before TLS v1.1 in order to randomize the IV of the
            * following record. Avoid spurious callbacks.
            */
            if(record.size() > 0)
               m_proc_fn(&record[0], record.size(), Alert());
            }
         else if(rec_type == ALERT)
            {
            Alert alert_msg(record);

            if(alert_msg.type() == Alert::NO_RENEGOTIATION)
               m_pending_state.reset();

            m_proc_fn(nullptr, 0, alert_msg);

            if(alert_msg.is_fatal())
               {
               if(auto active = active_state())
                  m_session_manager.remove_entry(active->server_hello()->session_id());
               }

            if(alert_msg.type() == Alert::CLOSE_NOTIFY)
               send_alert(Alert(Alert::CLOSE_NOTIFY)); // reply in kind

            if(alert_msg.type() == Alert::CLOSE_NOTIFY || alert_msg.is_fatal())
               {
               m_connection_closed = true;

               m_active_state.reset();
               m_pending_state.reset();

               return 0;
               }
            }
         else
            throw Unexpected_Message("Unexpected record type " +
                                     std::to_string(rec_type) +
                                     " from counterparty");
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
   if(heartbeat_sending_allowed())
      {
      Heartbeat_Message heartbeat(Heartbeat_Message::REQUEST,
                                  payload, payload_size);

      send_record(HEARTBEAT, heartbeat.contents());
      }
   }

void Channel::send_record_array(byte type, const byte input[], size_t length)
   {
   if(length == 0)
      return;

   /*
   * If using CBC mode without an explicit IV (SSL v3 or TLS v1.0),
   * send a single byte of plaintext to randomize the (implicit) IV of
   * the following main block. If using a stream cipher, or TLS v1.1
   * or higher, this isn't necessary.
   *
   * An empty record also works but apparently some implementations do
   * not like this (https://bugzilla.mozilla.org/show_bug.cgi?id=665814)
   *
   * See http://www.openssl.org/~bodo/tls-cbc.txt for background.
   */

   auto cipher_state = write_cipher_state_current();

   if(type == APPLICATION_DATA && cipher_state->cbc_without_explicit_iv())
      {
      write_record(cipher_state.get(), type, &input[0], 1);
      input += 1;
      length -= 1;
      }

   while(length)
      {
      const size_t sending = std::min(length, m_max_fragment);
      write_record(cipher_state.get(), type, &input[0], sending);

      input += sending;
      length -= sending;
      }
   }

void Channel::send_record(byte record_type, const std::vector<byte>& record)
   {
   send_record_array(record_type, &record[0], record.size());
   }

void Channel::write_record(Connection_Cipher_State* cipher_state,
                           byte record_type, const byte input[], size_t length)
   {
   if(length > m_max_fragment)
      throw Internal_Error("Record is larger than allowed fragment size");

   BOTAN_ASSERT(m_pending_state || m_active_state,
                "Some connection state exists");

   Protocol_Version record_version =
      (m_pending_state) ? (m_pending_state->version()) : (m_active_state->version());

   TLS::write_record(m_writebuf,
                     record_type,
                     input,
                     length,
                     record_version,
                     sequence_numbers(),
                     cipher_state,
                     m_rng);

   m_output_fn(&m_writebuf[0], m_writebuf.size());
   }

void Channel::send(const byte buf[], size_t buf_size)
   {
   if(!is_active())
      throw std::runtime_error("Data cannot be sent on inactive TLS connection");

   send_record_array(APPLICATION_DATA, buf, buf_size);
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
      m_pending_state.reset();

   if(alert.is_fatal())
      if(auto active = active_state())
         m_session_manager.remove_entry(active->server_hello()->session_id());

   if(alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal())
      {
      m_active_state.reset();
      m_pending_state.reset();

      m_connection_closed = true;
      }
   }

void Channel::secure_renegotiation_check(const Client_Hello* client_hello)
   {
   const bool secure_renegotiation = client_hello->secure_renegotiation();

   if(auto active = active_state())
      {
      const bool active_sr = active->client_hello()->secure_renegotiation();

      if(active_sr != secure_renegotiation)
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client changed its mind about secure renegotiation");
      }

   if(secure_renegotiation)
      {
      const std::vector<byte>& data = client_hello->renegotiation_info();

      if(data != secure_renegotiation_data_for_client_hello())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client sent bad values for secure renegotiation");
      }
   }

void Channel::secure_renegotiation_check(const Server_Hello* server_hello)
   {
   const bool secure_renegotiation = server_hello->secure_renegotiation();

   if(auto active = active_state())
      {
      const bool active_sr = active->client_hello()->secure_renegotiation();

      if(active_sr != secure_renegotiation)
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server changed its mind about secure renegotiation");
      }

   if(secure_renegotiation)
      {
      const std::vector<byte>& data = server_hello->renegotiation_info();

      if(data != secure_renegotiation_data_for_server_hello())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server sent bad values for secure renegotiation");
      }
   }

std::vector<byte> Channel::secure_renegotiation_data_for_client_hello() const
   {
   if(auto active = active_state())
      return active->client_finished()->verify_data();
   return std::vector<byte>();
   }

std::vector<byte> Channel::secure_renegotiation_data_for_server_hello() const
   {
   if(auto active = active_state())
      {
      std::vector<byte> buf = active->client_finished()->verify_data();
      buf += active->server_finished()->verify_data();
      return buf;
      }

   return std::vector<byte>();
   }

bool Channel::secure_renegotiation_supported() const
   {
   if(auto active = active_state())
      return active->server_hello()->secure_renegotiation();

   if(auto pending = pending_state())
      if(auto hello = pending->server_hello())
         return hello->secure_renegotiation();

   return false;
   }

SymmetricKey Channel::key_material_export(const std::string& label,
                                          const std::string& context,
                                          size_t length) const
   {
   if(auto active = active_state())
      {
      std::unique_ptr<KDF> prf(active->protocol_specific_prf());

      const secure_vector<byte>& master_secret =
         active->session_keys().master_secret();

      std::vector<byte> salt;
      salt += to_byte_vector(label);
      salt += active->client_hello()->random();
      salt += active->server_hello()->random();

      if(context != "")
         {
         size_t context_size = context.length();
         if(context_size > 0xFFFF)
            throw std::runtime_error("key_material_export context is too long");
         salt.push_back(get_byte<u16bit>(0, context_size));
         salt.push_back(get_byte<u16bit>(1, context_size));
         salt += to_byte_vector(context);
         }

      return prf->derive_key(length, master_secret, salt);
      }
   else
      throw std::runtime_error("Channel::key_material_export connection not active");
   }

}

}

