/*
* TLS Channel - implementation for TLS 1.3
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IMPL_13_H_
#define BOTAN_TLS_CHANNEL_IMPL_13_H_

#include <botan/internal/tls_channel_impl.h>

namespace Botan {

namespace TLS {

class Connection_Sequence_Numbers;
class Connection_Cipher_State;
class Handshake_State;

/**
* Generic interface for TLSv.12 endpoint
*/
class Channel_Impl_13 : public Channel_Impl
   {
   public:
      /**
      * Set up a new TLS 1.3 session
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS endpoint.
      * @param session_manager manages session state
      * @param rng a random number generator
      * @param policy specifies other connection policy information
      * @param is_server whether this is a server session or not
      * @param io_buf_sz This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
      explicit Channel_Impl_13(Callbacks& callbacks,
                               Session_Manager& session_manager,
                               RandomNumberGenerator& rng,
                               const Policy& policy,
                               bool is_server,
                               size_t io_buf_sz = Botan::TLS::Channel::IO_BUF_DEFAULT_SIZE);

      explicit Channel_Impl_13(const Channel_Impl_13&) = delete;

      Channel_Impl_13& operator=(const Channel_Impl_13&) = delete;

      virtual ~Channel_Impl_13();

      size_t received_data(const uint8_t buf[], size_t buf_size) override;

      /**
      * Inject plaintext intended for counterparty
      * Throws an exception if is_active() is false
      */
      void send(const uint8_t buf[], size_t buf_size) override;

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      void send_alert(const Alert& alert) override;

      /**
      * Send a close notification alert
      */
      void close() override { send_warning_alert(Alert::CLOSE_NOTIFY); }

      /**
      * @return true iff the connection is active for sending application data
      */
      bool is_active() const override;

      /**
      * @return true iff the connection has been definitely closed
      */
      bool is_closed() const override;

      /**
      * @return certificate chain of the peer (may be empty)
      */
      std::vector<X509_Certificate> peer_cert_chain() const override;

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      SymmetricKey key_material_export(const std::string& label,
                                       const std::string& context,
                                       size_t length) const override;

      /**
      * Attempt to renegotiate the session
      * @param force_full_renegotiation if true, require a full renegotiation,
      * otherwise allow session resumption
      */
      void renegotiate(bool force_full_renegotiation = false) override;

      /**
      * @return true iff the counterparty supports the secure
      * renegotiation extensions.
      */
      bool secure_renegotiation_supported() const override;

      /**
      * Perform a handshake timeout check. This does nothing unless
      * this is a DTLS channel with a pending handshake state, in
      * which case we check for timeout and potentially retransmit
      * handshake packets.
      */
      bool timeout_check() override;

   protected:
      Handshake_State& create_handshake_state(Protocol_Version version) override;

      Callbacks& callbacks() const { return m_callbacks; }
      Session_Manager& session_manager() { return m_session_manager; }
      RandomNumberGenerator& rng() { return m_rng; }
      const Policy& policy() const { return m_policy; }

   private:
      const Handshake_State* handshake_state() const { return m_handshake_state.get(); }

      void send_record(uint8_t record_type, const std::vector<uint8_t>& record);

      void send_record_array(uint16_t epoch, uint8_t record_type,
                             const uint8_t input[], size_t length);

      void write_record(Connection_Cipher_State* cipher_state,
                        uint16_t epoch, uint8_t type, const uint8_t input[], size_t length);

      Connection_Sequence_Numbers& sequence_numbers() const;

      std::shared_ptr<Connection_Cipher_State> read_cipher_state_epoch(uint16_t epoch) const;
      std::shared_ptr<Connection_Cipher_State> write_cipher_state_epoch(uint16_t epoch) const;

      void process_alert(const secure_vector<uint8_t>& record);

   private:
      /* callbacks */
      Callbacks& m_callbacks;

      /* external state */
      Session_Manager& m_session_manager;
      RandomNumberGenerator& m_rng;
      const Policy& m_policy;

      /* sequence number state */
      std::unique_ptr<Connection_Sequence_Numbers> m_sequence_numbers;

      /* handshake state */
      //TODO: Deciding whether single handshake_state is fine as pending/active is no longer
      // representing real state of handshake. Either single handshake state can be used, or
      // 4: plain / early_data / handshake_traffic / application_data_traffic
      std::unique_ptr<Handshake_State> m_handshake_state;

      /* cipher states for each epoch */
      std::map<uint16_t, std::shared_ptr<Connection_Cipher_State>> m_write_cipher_states;
      std::map<uint16_t, std::shared_ptr<Connection_Cipher_State>> m_read_cipher_states;

      const bool m_is_server;

      /* I/O buffers */
      secure_vector<uint8_t> m_writebuf;
      secure_vector<uint8_t> m_readbuf;
      secure_vector<uint8_t> m_record_buf;

      bool m_has_been_closed;
   };

}

}

#endif
