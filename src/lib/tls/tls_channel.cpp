/*
* TLS Channels
* (C) 2011,2012,2014,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_channel.h>
#include <botan/tls_messages.h>
#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/rounding.h>
#include <botan/internal/stl_util.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

size_t TLS::Channel::IO_BUF_DEFAULT_SIZE = 10*1024;

Channel::Channel(Callbacks& callbacks,
                 Session_Manager& session_manager,
                 RandomNumberGenerator& rng,
                 const Policy& policy,
                 bool is_datagram,
                 size_t reserved_io_buffer_size) :
   m_is_datagram(is_datagram),
   m_callbacks(callbacks),
   m_session_manager(session_manager),
   m_policy(policy),
   m_rng(rng)
   {
   init(reserved_io_buffer_size);
   }

Channel::Channel(output_fn out,
                 data_cb app_data_cb,
                 alert_cb alert_cb,
                 handshake_cb hs_cb,
                 handshake_msg_cb hs_msg_cb,
                 Session_Manager& session_manager,
                 RandomNumberGenerator& rng,
                 const Policy& policy,
                 bool is_datagram,
                 size_t io_buf_sz) :
    m_is_datagram(is_datagram),
    m_compat_callbacks(new Compat_Callbacks(out, app_data_cb, alert_cb, hs_cb, hs_msg_cb)),
    m_callbacks(*m_compat_callbacks.get()),
    m_session_manager(session_manager),
    m_policy(policy),
    m_rng(rng)
    {
    init(io_buf_sz);
    }

void Channel::init(size_t io_buf_sz)
   {
   /* epoch 0 is plaintext, thus null cipher state */
   m_write_cipher_states[0] = nullptr;
   m_read_cipher_states[0] = nullptr;

   m_writebuf.reserve(io_buf_sz);
   m_readbuf.reserve(io_buf_sz);
   }

void Channel::reset_state()
   {
   m_active_state.reset();
   m_pending_state.reset();
   m_readbuf.clear();
   m_write_cipher_states.clear();
   m_read_cipher_states.clear();
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

std::shared_ptr<Connection_Cipher_State> Channel::read_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_read_cipher_states.find(epoch);
   if(i == m_read_cipher_states.end())
      throw Internal_Error("TLS::Channel No read cipherstate for epoch " + std::to_string(epoch));
   return i->second;
   }

std::shared_ptr<Connection_Cipher_State> Channel::write_cipher_state_epoch(uint16_t epoch) const
   {
   auto i = m_write_cipher_states.find(epoch);
   if(i == m_write_cipher_states.end())
      throw Internal_Error("TLS::Channel No write cipherstate for epoch " + std::to_string(epoch));
   return i->second;
   }

std::vector<X509_Certificate> Channel::peer_cert_chain() const
   {
   if(auto active = active_state())
      return get_peer_cert_chain(*active);
   return std::vector<X509_Certificate>();
   }

Handshake_State& Channel::create_handshake_state(Protocol_Version version)
   {
   if(pending_state())
      throw Internal_Error("create_handshake_state called during handshake");

   if(auto active = active_state())
      {
      Protocol_Version active_version = active->version();

      if(active_version.is_datagram_protocol() != version.is_datagram_protocol())
         throw Exception("Active state using version " +
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

   using namespace std::placeholders;

   std::unique_ptr<Handshake_IO> io;
   if(version.is_datagram_protocol())
      {
      io.reset(new Datagram_Handshake_IO(
                  std::bind(&Channel::send_record_under_epoch, this, _1, _2, _3),
                  sequence_numbers(),
                  static_cast<uint16_t>(m_policy.dtls_default_mtu()),
                  m_policy.dtls_initial_timeout(),
                  m_policy.dtls_maximum_timeout()));
      }
   else
      {
      io.reset(new Stream_Handshake_IO(std::bind(&Channel::send_record, this, _1, _2)));
      }

   m_pending_state.reset(new_handshake_state(io.release()));

   if(auto active = active_state())
      m_pending_state->set_version(active->version());

   return *m_pending_state.get();
   }

bool Channel::timeout_check()
   {
   if(m_pending_state)
      return m_pending_state->handshake_io().timeout_check();

   //FIXME: scan cipher suites and remove epochs older than 2*MSL
   return false;
   }

void Channel::renegotiate(bool force_full_renegotiation)
   {
   if(pending_state()) // currently in handshake?
      return;

   if(auto active = active_state())
      initiate_handshake(create_handshake_state(active->version()),
                         force_full_renegotiation);
   else
      throw Exception("Cannot renegotiate on inactive connection");
   }

void Channel::change_cipher_spec_reader(Connection_Side side)
   {
   auto pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(),
                "Have received server hello");

   if(pending->server_hello()->compression_method() != NO_COMPRESSION)
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

void Channel::change_cipher_spec_writer(Connection_Side side)
   {
   auto pending = pending_state();

   BOTAN_ASSERT(pending && pending->server_hello(),
                "Have received server hello");

   if(pending->server_hello()->compression_method() != NO_COMPRESSION)
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

bool Channel::is_active() const
   {
   return (active_state() != nullptr);
   }

bool Channel::is_closed() const
   {
   if(active_state() || pending_state())
      return false;

   /*
   * If no active or pending state, then either we had a connection
   * and it has been closed, or we are a server which has never
   * received a connection. This case is detectable by also lacking
   * m_sequence_numbers
   */
   return (m_sequence_numbers != nullptr);
   }

void Channel::activate_session()
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

size_t Channel::received_data(const std::vector<uint8_t>& buf)
   {
   return this->received_data(buf.data(), buf.size());
   }

size_t Channel::received_data(const uint8_t input[], size_t input_size)
   {
   try
      {
      while(!is_closed() && input_size)
         {
         secure_vector<uint8_t> record_data;
         uint64_t record_sequence = 0;
         Record_Type record_type = NO_RECORD;
         Protocol_Version record_version;

         size_t consumed = 0;

         Record_Raw_Input raw_input(input, input_size, consumed, m_is_datagram);
         Record record(record_data, &record_sequence, &record_version, &record_type);
         const size_t needed =
            read_record(m_readbuf,
                        raw_input,
                        record,
                        m_sequence_numbers.get(),
                        std::bind(&TLS::Channel::read_cipher_state_epoch, this,
                                  std::placeholders::_1));

         BOTAN_ASSERT(consumed > 0, "Got to eat something");

         BOTAN_ASSERT(consumed <= input_size,
                      "Record reader consumed sane amount");

         input += consumed;
         input_size -= consumed;

         BOTAN_ASSERT(input_size == 0 || needed == 0,
                      "Got a full record or consumed all input");

         if(input_size == 0 && needed != 0)
            return needed; // need more data to complete record

         if(record_data.size() > MAX_PLAINTEXT_SIZE)
            throw TLS_Exception(Alert::RECORD_OVERFLOW,
                                "TLS plaintext record is larger than allowed maximum");

         if(record_type == HANDSHAKE || record_type == CHANGE_CIPHER_SPEC)
            {
            process_handshake_ccs(record_data, record_sequence, record_type, record_version);
            }
         else if(record_type == APPLICATION_DATA)
            {
            process_application_data(record_sequence, record_data);
            }
         else if(record_type == ALERT)
            {
            process_alert(record_data);
            }
         else if(record_type != NO_RECORD)
            throw Unexpected_Message("Unexpected record type " +
                                     std::to_string(record_type) +
                                     " from counterparty");
         }

      return 0; // on a record boundary
      }
   catch(TLS_Exception& e)
      {
      send_fatal_alert(e.type());
      throw;
      }
   catch(Integrity_Failure&)
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

void Channel::process_handshake_ccs(const secure_vector<uint8_t>& record,
                                    uint64_t record_sequence,
                                    Record_Type record_type,
                                    Protocol_Version record_version)
   {
   if(!m_pending_state)
      {
      // No pending handshake, possibly new:
      if(record_version.is_datagram_protocol())
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
               m_active_state->handshake_io().add_record(unlock(record),
                                                         record_type,
                                                         record_sequence);
               }
            }
         else if(record_sequence == 0)
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
      m_pending_state->handshake_io().add_record(unlock(record),
                                                 record_type,
                                                 record_sequence);

      while(auto pending = m_pending_state.get())
         {
         auto msg = pending->get_next_handshake_msg();

         if(msg.first == HANDSHAKE_NONE) // no full handshake yet
            break;

         process_handshake_msg(active_state(), *pending,
                               msg.first, msg.second);
         }
      }
   }

void Channel::process_application_data(uint64_t seq_no, const secure_vector<uint8_t>& record)
   {
   if(!active_state())
      throw Unexpected_Message("Application data before handshake done");

   /*
   * OpenSSL among others sends empty records in versions
   * before TLS v1.1 in order to randomize the IV of the
   * following record. Avoid spurious callbacks.
   */
   if(record.size() > 0)
      callbacks().tls_record_received(seq_no, record.data(), record.size());
   }

void Channel::process_alert(const secure_vector<uint8_t>& record)
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
       reset_state();
       }
    }


void Channel::write_record(Connection_Cipher_State* cipher_state, uint16_t epoch,
                           uint8_t record_type, const uint8_t input[], size_t length)
   {
   BOTAN_ASSERT(m_pending_state || m_active_state, "Some connection state exists");

   Protocol_Version record_version =
      (m_pending_state) ? (m_pending_state->version()) : (m_active_state->version());

   Record_Message record_message(record_type, 0, input, length);

   TLS::write_record(m_writebuf,
                     record_message,
                     record_version,
                     sequence_numbers().next_write_sequence(epoch),
                     cipher_state,
                     m_rng);

   callbacks().tls_emit_data(m_writebuf.data(), m_writebuf.size());
   }

void Channel::send_record_array(uint16_t epoch, uint8_t type, const uint8_t input[], size_t length)
   {
   if(length == 0)
      return;

   /*
   * In versions without an explicit IV field (only TLS v1.0 now that
   * SSLv3 has been removed) send a single byte record first to randomize
   * the following (implicit) IV of the following record.
   *
   * This isn't needed in TLS v1.1 or higher.
   *
   * An empty record also works but apparently some implementations do
   * not like this (https://bugzilla.mozilla.org/show_bug.cgi?id=665814)
   *
   * See http://www.openssl.org/~bodo/tls-cbc.txt for background.
   */

   auto cipher_state = write_cipher_state_epoch(epoch);

   if(type == APPLICATION_DATA && m_active_state->version().supports_explicit_cbc_ivs() == false)
      {
      write_record(cipher_state.get(), epoch, type, input, 1);
      input += 1;
      length -= 1;
      }

   while(length)
      {
      const size_t sending = std::min<size_t>(length, MAX_PLAINTEXT_SIZE);
      write_record(cipher_state.get(), epoch, type, input, sending);

      input += sending;
      length -= sending;
      }
   }

void Channel::send_record(uint8_t record_type, const std::vector<uint8_t>& record)
   {
   send_record_array(sequence_numbers().current_write_epoch(),
                     record_type, record.data(), record.size());
   }

void Channel::send_record_under_epoch(uint16_t epoch, uint8_t record_type,
                                      const std::vector<uint8_t>& record)
   {
   send_record_array(epoch, record_type, record.data(), record.size());
   }

void Channel::send(const uint8_t buf[], size_t buf_size)
   {
   if(!is_active())
      throw Exception("Data cannot be sent on inactive TLS connection");

   send_record_array(sequence_numbers().current_write_epoch(),
                     APPLICATION_DATA, buf, buf_size);
   }

void Channel::send(const std::string& string)
   {
   this->send(reinterpret_cast<const uint8_t*>(string.c_str()), string.size());
   }

void Channel::send_alert(const Alert& alert)
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
      if(auto active = active_state())
         m_session_manager.remove_entry(active->server_hello()->session_id());

   if(alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal())
      reset_state();
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
      const std::vector<uint8_t>& data = client_hello->renegotiation_info();

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
      const std::vector<uint8_t>& data = server_hello->renegotiation_info();

      if(data != secure_renegotiation_data_for_server_hello())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Server sent bad values for secure renegotiation");
      }
   }

std::vector<uint8_t> Channel::secure_renegotiation_data_for_client_hello() const
   {
   if(auto active = active_state())
      return active->client_finished()->verify_data();
   return std::vector<uint8_t>();
   }

std::vector<uint8_t> Channel::secure_renegotiation_data_for_server_hello() const
   {
   if(auto active = active_state())
      {
      std::vector<uint8_t> buf = active->client_finished()->verify_data();
      buf += active->server_finished()->verify_data();
      return buf;
      }

   return std::vector<uint8_t>();
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

      const secure_vector<uint8_t>& master_secret =
         active->session_keys().master_secret();

      std::vector<uint8_t> salt;
      salt += active->client_hello()->random();
      salt += active->server_hello()->random();

      if(context != "")
         {
         size_t context_size = context.length();
         if(context_size > 0xFFFF)
            throw Exception("key_material_export context is too long");
         salt.push_back(get_byte(0, static_cast<uint16_t>(context_size)));
         salt.push_back(get_byte(1, static_cast<uint16_t>(context_size)));
         salt += to_byte_vector(context);
         }

      return prf->derive_key(length, master_secret, salt, to_byte_vector(label));
      }
   else
      throw Exception("Channel::key_material_export connection not active");
   }

}

}
