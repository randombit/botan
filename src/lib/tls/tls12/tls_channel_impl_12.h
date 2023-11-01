/*
* TLS Channel - implementation for TLS 1.2
* (C) 2011,2012,2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IMPL_12_H_
#define BOTAN_TLS_CHANNEL_IMPL_12_H_

#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>
#include <botan/internal/tls_channel_impl.h>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Botan {

class X509_Certificate;

namespace TLS {

class Connection_Cipher_State;
class Connection_Sequence_Numbers;
class Handshake_State;
class Handshake_Message;
class Client_Hello_12;
class Server_Hello_12;
class Policy;

/**
* Generic interface for TLSv.12 endpoint
*/
class Channel_Impl_12 : public Channel_Impl {
   public:
      typedef std::function<void(const uint8_t[], size_t)> output_fn;
      typedef std::function<void(const uint8_t[], size_t)> data_cb;
      typedef std::function<void(Alert, const uint8_t[], size_t)> alert_cb;
      typedef std::function<bool(const Session&)> handshake_cb;
      typedef std::function<void(const Handshake_Message&)> handshake_msg_cb;

      /**
      * Set up a new TLS session
      *
      * @param callbacks contains a set of callback function references
      *        required by the TLS endpoint.
      * @param session_manager manages session state
      * @param rng a random number generator
      * @param policy specifies other connection policy information
      * @param is_server whether this is a server session or not
      * @param is_datagram whether this is a DTLS session
      * @param io_buf_sz This many bytes of memory will
      *        be preallocated for the read and write buffers. Smaller
      *        values just mean reallocations and copies are more likely.
      */
      explicit Channel_Impl_12(const std::shared_ptr<Callbacks>& callbacks,
                               const std::shared_ptr<Session_Manager>& session_manager,
                               const std::shared_ptr<RandomNumberGenerator>& rng,
                               const std::shared_ptr<const Policy>& policy,
                               bool is_server,
                               bool is_datagram,
                               size_t io_buf_sz = TLS::Channel::IO_BUF_DEFAULT_SIZE);

      explicit Channel_Impl_12(const Channel_Impl_12&) = delete;

      Channel_Impl_12& operator=(const Channel_Impl_12&) = delete;

      ~Channel_Impl_12() override;

      size_t from_peer(std::span<const uint8_t> data) override;
      void to_peer(std::span<const uint8_t> data) override;

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      void send_alert(const Alert& alert) override;

      /**
      * @return true iff the TLS handshake completed successfully
      */
      bool is_handshake_complete() const override;

      /**
      * @return true iff the connection is active for sending application data
      */
      bool is_active() const override;

      /**
      * @return true iff the connection has been definitely closed
      */
      bool is_closed() const override;

      bool is_closed_for_reading() const override { return is_closed(); }

      bool is_closed_for_writing() const override { return is_closed(); }

      /**
      * @return certificate chain of the peer (may be empty)
      */
      std::vector<X509_Certificate> peer_cert_chain() const override;

      /**
      * Note: Raw public key for authentication (RFC7250) is currently not
      *       implemented for TLS 1.2.
      *
      * @return raw public key of the peer (will be nullptr)
      */
      std::shared_ptr<const Public_Key> peer_raw_public_key() const override { return nullptr; }

      std::optional<std::string> external_psk_identity() const override;

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      SymmetricKey key_material_export(std::string_view label, std::string_view context, size_t length) const override;

      /**
      * Attempt to renegotiate the session
      * @param force_full_renegotiation if true, require a full renegotiation,
      * otherwise allow session resumption
      */
      void renegotiate(bool force_full_renegotiation = false) override;

      /**
      * Attempt to update the session's traffic key material
      * Note that this is possible with a TLS 1.3 channel, only.
      *
      * @param request_peer_update if true, require a reciprocal key update
      */
      void update_traffic_keys(bool request_peer_update = false) override;

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
      virtual void process_handshake_msg(const Handshake_State* active_state,
                                         Handshake_State& pending_state,
                                         Handshake_Type type,
                                         const std::vector<uint8_t>& contents,
                                         bool epoch0_restart) = 0;

      Handshake_State& create_handshake_state(Protocol_Version version);
      virtual std::unique_ptr<Handshake_State> new_handshake_state(std::unique_ptr<class Handshake_IO> io) = 0;

      void inspect_handshake_message(const Handshake_Message& msg);

      void activate_session();

      void change_cipher_spec_reader(Connection_Side side);

      void change_cipher_spec_writer(Connection_Side side);

      /* secure renegotiation handling */

      void secure_renegotiation_check(const Client_Hello_12* client_hello);
      void secure_renegotiation_check(const Server_Hello_12* server_hello);

      std::vector<uint8_t> secure_renegotiation_data_for_client_hello() const;
      std::vector<uint8_t> secure_renegotiation_data_for_server_hello() const;

      RandomNumberGenerator& rng() { return *m_rng; }

      Session_Manager& session_manager() { return *m_session_manager; }

      const Policy& policy() const { return *m_policy; }

      Callbacks& callbacks() const { return *m_callbacks; }

      void reset_active_association_state();

      virtual void initiate_handshake(Handshake_State& state, bool force_full_renegotiation) = 0;

      virtual std::vector<X509_Certificate> get_peer_cert_chain(const Handshake_State& state) const = 0;

   private:
      void send_record(Record_Type record_type, const std::vector<uint8_t>& record);

      void send_record_under_epoch(uint16_t epoch, Record_Type record_type, const std::vector<uint8_t>& record);

      void send_record_array(uint16_t epoch, Record_Type record_type, const uint8_t input[], size_t length);

      void write_record(
         Connection_Cipher_State* cipher_state, uint16_t epoch, Record_Type type, const uint8_t input[], size_t length);

      void reset_state();

      Connection_Sequence_Numbers& sequence_numbers() const;

      std::shared_ptr<Connection_Cipher_State> read_cipher_state_epoch(uint16_t epoch) const;

      std::shared_ptr<Connection_Cipher_State> write_cipher_state_epoch(uint16_t epoch) const;

      const Handshake_State* active_state() const { return m_active_state.get(); }

      const Handshake_State* pending_state() const { return m_pending_state.get(); }

      /* methods to handle incoming traffic through Channel_Impl_12::receive_data. */
      void process_handshake_ccs(const secure_vector<uint8_t>& record,
                                 uint64_t record_sequence,
                                 Record_Type record_type,
                                 Protocol_Version record_version,
                                 bool epoch0_restart);

      void process_application_data(uint64_t req_no, const secure_vector<uint8_t>& record);

      void process_alert(const secure_vector<uint8_t>& record);

      const bool m_is_server;
      const bool m_is_datagram;

      /* callbacks */
      std::shared_ptr<Callbacks> m_callbacks;

      /* external state */
      std::shared_ptr<Session_Manager> m_session_manager;
      std::shared_ptr<const Policy> m_policy;
      std::shared_ptr<RandomNumberGenerator> m_rng;

      /* sequence number state */
      std::unique_ptr<Connection_Sequence_Numbers> m_sequence_numbers;

      /* pending and active connection states */
      std::unique_ptr<Handshake_State> m_active_state;
      std::unique_ptr<Handshake_State> m_pending_state;

      /* cipher states for each epoch */
      std::map<uint16_t, std::shared_ptr<Connection_Cipher_State>> m_write_cipher_states;
      std::map<uint16_t, std::shared_ptr<Connection_Cipher_State>> m_read_cipher_states;

      /* I/O buffers */
      secure_vector<uint8_t> m_writebuf;
      secure_vector<uint8_t> m_readbuf;
      secure_vector<uint8_t> m_record_buf;

      bool m_has_been_closed;
};

}  // namespace TLS

}  // namespace Botan

#endif
