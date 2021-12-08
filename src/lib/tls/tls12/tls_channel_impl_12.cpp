/*
* TLS Channels
* (C) 2011,2012,2014,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_policy.h>
#include <botan/tls_messages.h>
#include <botan/kdf.h>
#include <botan/internal/tls_channel_impl_12.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/loadstor.h>
#include <botan/x509cert.h>

namespace Botan {

namespace TLS {


Channel_Impl_12::Channel_Impl_12(Callbacks& callbacks,
                                 Session_Manager& session_manager,
                                 RandomNumberGenerator& rng,
                                 const Policy& policy,
                                 bool is_server,
                                 bool is_datagram,
                                 size_t reserved_io_buffer_size) :
   m_is_server(is_server),
   m_is_datagram(is_datagram),
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_policy(policy),
   m_rng(rng),
   m_has_been_closed(false)
   {
   /* epoch 0 is plaintext, thus null cipher state */
   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = nullptr;

   m_writebuf.reserve(reserved_io_buffer_size);
   m_readbuf.reserve(reserved_io_buffer_size);
   }

void Channel_Impl_12::reset_state()
   {
   m_active_state.reset();
   m_pending_state.reset();
   m_readbuf.clear();
   m_write_cipher_states.clear();
   m_read_cipher_states.clear();
   }

void Channel_Impl_12::reset_active_association_state()
   {
   // This operation only makes sense for DTLS
   BOTAN_ASSERT_NOMSG(m_is_datagram);
   m_active_state.reset();
   m_read_cipher_states.clear();
   m_write_cipher_states.clear();

   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = nullptr;

   if(m_sequence_numbers)
      m_sequence_numbers->reset();
   }

Channel_Impl_12::~Channel_Impl_12()
   {
   // So unique_ptr destructors run correctly
   }

Connection_Sequence_Numbers& Channel_Impl_12::sequence_numbers() const
   {
   BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
   return *m_sequence_numbers;
   }

std::shared_ptr<Connection_Cipher_State> Channel_Impl_12::read_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_read_cipher_states.find(epoch);
   if(i == m_read_cipher_states.end())
      { throw Internal_Error("TLS::Channel_Impl_12 No read cipherstate for epoch " + std::to_string(epoch)); }
   return i->second;
   }

std::shared_ptr<Connection_Cipher_State> Channel_Impl_12::write_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_write_cipher_states.find(epoch);
   if(i == m_write_cipher_states.end())
      { throw Internal_Error("TLS::Channel_Impl_12 No write cipherstate for epoch " + std::to_string(epoch)); }
   return i->second;
   }

std::vector<X509_Certificate> Channel_Impl_12::peer_cert_chain() const
   {
   if(auto active = active_state())
      return get_peer_cert_chain(*active);
   return std::vector<X509_Certificate>();
   }

bool Channel_Impl_12::save_session(const Session& session)
   {
   return callbacks().tls_session_established(session);
   }

Handshake_State& Channel_Impl_12::create_handshake_state(Protocol_Version version)
   {
   if(pending_state())
      throw Internal_Error("create_handshake_state called during handshake");

   if(auto active = active_state())
      {
      Protocol_Version active_version = active->version();

      if(active_version.is_datagram_protocol() != version.is_datagram_protocol())
         {
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Active state using version " + active_version.to_string() +
                             " cannot change to " + version.to_string() + " in pending");
         }
      }

   if(!m_sequence_numbers)
      {
      if(version.is_datagram_protocol())
         m_sequence_numbers.reset(new Datagram_Sequence_Numbers);
      else
         m_sequence_numbers.reset(new Stream_Sequence_Numbers);
      }

   using namespace std::placeholders;

   std::unique_ptr<Handshake_IO> io;
   if(version.is_datagram_protocol())
      {
      io.reset(new Datagram_Handshake_IO(
                  std::bind(&Channel_Impl_12::send_record_under_epoch, this, _1, _2, _3),
                  sequence_numbers(),
                  static_cast<uint16_t>(m_policy.dtls_default_mtu()),
                  m_policy.dtls_initial_timeout(),
                  m_policy.dtls_maximum_timeout()));
      }
   else
      {
      io.reset(new Stream_Handshake_IO(std::bind(&Channel_Impl_12::send_record, this, _1, _2)));
      }

   m_pending_state = new_handshake_state(std::move(io));

   if(auto active = active_state())
      m_pending_state->set_version(active->version());

   return *m_pending_state.get();
   }

bool Channel_Impl_12::timeout_check()
   {
   if(m_pending_state)
      return m_pending_state->handshake_io().timeout_check();

   //FIXME: scan cipher suites and remove epochs older than 2*MSL
   return false;
   }

void Channel_Impl_12::renegotiate(bool force_full_renegotiation)
   {
   if(pending_state()) // currently in handshake?
      return;

   if(auto active = active_state())
      {
      if(force_full_renegotiation == false)
         force_full_renegotiation = !policy().allow_resumption_for_renegotiation();

      initiate_handshake(create_handshake_state(active->version()),
                         force_full_renegotiation);
      }
   else
      throw Invalid_State("Cannot renegotiate on inactive connection");
   }

void Channel_Impl_12::change_cipher_spec_reader(Connection_Side side)
   {
   auto pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(),
                "Have received server hello");

   if(pending->server_hello()->compression_method() != 0)
      throw Internal_Error("Negotiated unknown compression algorithm");

   sequence_numbers().new_read_cipher_state();

   const uint16_t epoch = sequence_numbers().current_read_epoch();

   BOTAN_ASSERT(m_read_cipher_states.count(epoch) == 0,
                "No read cipher state currently set for next epoch");

   // flip side as we are reading
   std::shared_ptr<Connection_Cipher_State> read_state(
      new Connection_Cipher_State(pending->version(),
                                  (side == CLIENT) ? SERVER : CLIENT,
                                  false,
                                  pending->ciphersuite(),
                                  pending->session_keys(),
                                  pending->server_hello()->supports_encrypt_then_mac()));

   m_read_cipher_states[epoch] = read_state;
   }

void Channel_Impl_12::change_cipher_spec_writer(Connection_Side side)
   {
   auto pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(),
                "Have received server hello");

   if(pending->server_hello()->compression_method() != 0)
      throw Internal_Error("Negotiated unknown compression algorithm");

   sequence_numbers().new_write_cipher_state();

   const uint16_t epoch = sequence_numbers().current_write_epoch();

   BOTAN_ASSERT(m_write_cipher_states.count(epoch) == 0,
                "No write cipher state currently set for next epoch");

   std::shared_ptr<Connection_Cipher_State> write_state(
      new Connection_Cipher_State(pending->version(),
                                  side,
                                  true,
                                  pending->ciphersuite(),
                                  pending->session_keys(),
                                  pending->server_hello()->supports_encrypt_then_mac()));

   m_write_cipher_states[epoch] = write_state;
   }

bool Channel_Impl_12::is_active() const
   {
   if(is_closed())
      return false;
   return (active_state() != nullptr);
   }

bool Channel_Impl_12::is_closed() const
   {
   return m_has_been_closed;
   }

void Channel_Impl_12::activate_session()
   {
   std::swap(m_active_state, m_pending_state);
   m_pending_state.reset();

   if(!m_active_state->version().is_datagram_protocol())
      {
      // TLS is easy just remove all but the current state
      const uint16_t current_epoch = sequence_numbers().current_write_epoch();

      const auto not_current_epoch =
         [current_epoch](uint16_t epoch) { return (epoch != current_epoch); };

      map_remove_if(not_current_epoch, m_write_cipher_states);
      map_remove_if(not_current_epoch, m_read_cipher_states);
      }

   callbacks().tls_session_activated();
   }

size_t Channel_Impl_12::received_data(const uint8_t input[], size_t input_size)
   {
   const bool allow_epoch0_restart = m_is_datagram && m_is_server && policy().allow_dtls_epoch0_restart();

   try
      {
      while(input_size)
         {
         size_t consumed = 0;

         auto get_epoch = [this](uint16_t epoch) { return read_cipher_state_epoch(epoch); };

         const Record_Header record =
            read_record(m_is_datagram,
                        m_readbuf,
                        input,
                        input_size,
                        consumed,
                        m_record_buf,
                        m_sequence_numbers.get(),
                        get_epoch,
                        allow_epoch0_restart);

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

         // Ignore invalid records in DTLS
         if(m_is_datagram && record.type() == NO_RECORD)
            {
            return 0;
            }

         if(m_record_buf.size() > MAX_PLAINTEXT_SIZE)
            throw TLS_Exception(Alert::RECORD_OVERFLOW,
                                "TLS plaintext record is larger than allowed maximum");


         const bool epoch0_restart = m_is_datagram && record.epoch() == 0 && active_state();
         BOTAN_ASSERT_IMPLICATION(epoch0_restart, allow_epoch0_restart, "Allowed state");

         const bool initial_record = epoch0_restart || (!pending_state() && !active_state());

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
            else if(auto pending = pending_state())
               {
               if(pending->server_hello() != nullptr && record.version() != pending->version())
                  {
                  if(record.version() != pending->version())
                     {
                     throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                         "Received unexpected record version");
                     }
                  }
               }
            else if(auto active = active_state())
               {
               if(record.version() != active->version())
                  {
                  throw TLS_Exception(Alert::PROTOCOL_VERSION,
                                      "Received unexpected record version");
                  }
               }
            }

         if(record.type() == HANDSHAKE || record.type() == CHANGE_CIPHER_SPEC)
            {
            if(m_has_been_closed)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received handshake data after connection closure");
            process_handshake_ccs(m_record_buf, record.sequence(), record.type(), record.version(), epoch0_restart);
            }
         else if(record.type() == APPLICATION_DATA)
            {
            if(m_has_been_closed)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Received application data after connection closure");
            if(pending_state() != nullptr)
               throw TLS_Exception(Alert::UNEXPECTED_MESSAGE, "Can't interleave application and handshake data");
            process_application_data(record.sequence(), m_record_buf);
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
   }

void Channel_Impl_12::process_handshake_ccs(const secure_vector<uint8_t>& record,
      uint64_t record_sequence,
      Record_Type record_type,
      Protocol_Version record_version,
      bool epoch0_restart)
   {
   if(!m_pending_state)
      {
      // No pending handshake, possibly new:
      if(record_version.is_datagram_protocol() && !epoch0_restart)
         {
         if(m_sequence_numbers)
            {
            /*
            * Might be a peer retransmit under epoch - 1 in which
            * case we must retransmit last flight
            */
            sequence_numbers().read_accept(record_sequence);

            const uint16_t epoch = record_sequence >> 48;

            if(epoch == sequence_numbers().current_read_epoch())
               {
               create_handshake_state(record_version);
               }
            else if(epoch == sequence_numbers().current_read_epoch() - 1)
               {
               BOTAN_ASSERT(m_active_state, "Have active state here");
               m_active_state->handshake_io().add_record(record.data(),
                                                         record.size(),
                                                         record_type,
                                                         record_sequence);
               }
            }
         else
            {
            create_handshake_state(record_version);
            }
         }
      else
         {
         create_handshake_state(record_version);
         }
      }

   // May have been created in above conditional
   if(m_pending_state)
      {
      m_pending_state->handshake_io().add_record(record.data(),
                                                 record.size(),
                                                 record_type,
                                                 record_sequence);

      while(auto pending = m_pending_state.get())
         {
         auto msg = pending->get_next_handshake_msg();

         if(msg.first == HANDSHAKE_NONE) // no full handshake yet
            break;

         process_handshake_msg(active_state(), *pending,
                               msg.first, msg.second, epoch0_restart);

         if(!m_pending_state)
            break;
         }
      }
   }

void Channel_Impl_12::process_application_data(uint64_t seq_no, const secure_vector<uint8_t>& record)
   {
   if(!active_state())
      throw Unexpected_Message("Application data before handshake done");

   callbacks().tls_record_received(seq_no, record.data(), record.size());
   }

void Channel_Impl_12::process_alert(const secure_vector<uint8_t>& record)
    {
    Alert alert_msg(record);

    if(alert_msg.type() == Alert::NO_RENEGOTIATION)
       m_pending_state.reset();

    callbacks().tls_alert(alert_msg);

    if(alert_msg.is_fatal())
       {
       if(auto active = active_state())
          m_session_manager.remove_entry(active->server_hello()->session_id());
       }

    if(alert_msg.type() == Alert::CLOSE_NOTIFY)
       send_warning_alert(Alert::CLOSE_NOTIFY); // reply in kind

    if(alert_msg.type() == Alert::CLOSE_NOTIFY || alert_msg.is_fatal())
       {
       m_has_been_closed = true;
       }
    }

void Channel_Impl_12::write_record(Connection_Cipher_State* cipher_state, uint16_t epoch,
                                   uint8_t record_type, const uint8_t input[], size_t length)
   {
   BOTAN_ASSERT(m_pending_state || m_active_state, "Some connection state exists");

   const Protocol_Version record_version =
      (m_pending_state) ? (m_pending_state->version()) : (m_active_state->version());

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

void Channel_Impl_12::send_record_array(uint16_t epoch, uint8_t type, const uint8_t input[], size_t length)
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

void Channel_Impl_12::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   send_record_array(sequence_numbers().current_write_epoch(),
                     record_type, record.data(), record.size());
   }

void Channel_Impl_12::send_record_under_epoch(uint16_t epoch, uint8_t record_type,
      const std::vector<uint8_t>& record)
   {
   send_record_array(epoch, record_type, record.data(), record.size());
   }

void Channel_Impl_12::send(const uint8_t buf[], size_t buf_size)
   {
   if(!is_active())
      throw Invalid_State("Data cannot be sent on inactive TLS connection");

   send_record_array(sequence_numbers().current_write_epoch(),
                     APPLICATION_DATA, buf, buf_size);
   }

void Channel_Impl_12::send_alert(const Alert& alert)
   {
   if(alert.is_valid() && !is_closed())
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
   {
      if(auto active = active_state())
      {
         m_session_manager.remove_entry(active->server_hello()->session_id());
      }
      reset_state();
   }

   if(alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal())
      {
      m_has_been_closed = true;
      }
   }

void Channel_Impl_12::secure_renegotiation_check(const Client_Hello* client_hello)
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
      const std::vector<uint8_t>& data = client_hello->renegotiation_info();

      if(data != secure_renegotiation_data_for_client_hello())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client sent bad values for secure renegotiation");
      }
   }

void Channel_Impl_12::secure_renegotiation_check(const Server_Hello* server_hello)
   {
   const bool secure_renegotiation = server_hello->secure_renegotiation();

   if(auto active = active_state())
      {
      const bool active_sr = active->server_hello()->secure_renegotiation();

      if(active_sr != secure_renegotiation)
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server changed its mind about secure renegotiation");
      }

   if(secure_renegotiation)
      {
      const std::vector<uint8_t>& data = server_hello->renegotiation_info();

      if(data != secure_renegotiation_data_for_server_hello())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server sent bad values for secure renegotiation");
      }
   }

std::vector<uint8_t> Channel_Impl_12::secure_renegotiation_data_for_client_hello() const
   {
   if(auto active = active_state())
      return active->client_finished()->verify_data();
   return std::vector<uint8_t>();
   }

std::vector<uint8_t> Channel_Impl_12::secure_renegotiation_data_for_server_hello() const
   {
   if(auto active = active_state())
      {
      std::vector<uint8_t> buf = active->client_finished()->verify_data();
      buf += active->server_finished()->verify_data();
      return buf;
      }

   return std::vector<uint8_t>();
   }

bool Channel_Impl_12::secure_renegotiation_supported() const
   {
   if(auto active = active_state())
      return active->server_hello()->secure_renegotiation();

   if(auto pending = pending_state())
      if(auto hello = pending->server_hello())
         return hello->secure_renegotiation();

   return false;
   }

SymmetricKey Channel_Impl_12::key_material_export(const std::string& label,
      const std::string& context,
      size_t length) const
   {
   if(auto active = active_state())
      {
      if(pending_state() != nullptr)
         { throw Invalid_State("Channel_Impl_12::key_material_export cannot export during renegotiation"); }

      auto prf = active->protocol_specific_prf();

      const secure_vector<uint8_t>& master_secret =
         active->session_keys().master_secret();

      std::vector<uint8_t> salt;
      salt += active->client_hello()->random();
      salt += active->server_hello()->random();

      if(context != "")
         {
         size_t context_size = context.length();
         if(context_size > 0xFFFF)
            throw Invalid_Argument("key_material_export context is too long");
         salt.push_back(get_byte<0>(static_cast<uint16_t>(context_size)));
         salt.push_back(get_byte<1>(static_cast<uint16_t>(context_size)));
         salt += to_byte_vector(context);
         }

      return prf->derive_key(length, master_secret, salt, to_byte_vector(label));
      }
   else
      {
      throw Invalid_State("Channel_Impl_12::key_material_export connection not active");
      }
   }

}

}
