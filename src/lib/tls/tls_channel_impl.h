/*
* TLS Channel
* (C) 2011,2012,2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_IMPL_H_
#define BOTAN_TLS_CHANNEL_IMPL_H_

#include <botan/tls_channel.h>
#include <botan/tls_magic.h>
#include <botan/tls_version.h>

#include <memory>
#include <utility>
#include <vector>

namespace Botan {

class Credentials_Manager;
class X509_Certificate;

namespace TLS {

class Client;
class Server;

enum class Record_Type : uint8_t {
   Invalid = 0,  // RFC 8446 (TLS 1.3)

   ChangeCipherSpec = 20,
   Alert = 21,
   Handshake = 22,
   ApplicationData = 23,

   Heartbeat = 24,  // RFC 6520 (TLS 1.3)
};

class Channel_Impl {
   public:
      virtual ~Channel_Impl() = default;

      /**
      * Inject TLS traffic received from counterparty
      * @return a hint as the how many more bytes we need to q the
      *         current record (this may be 0 if on a record boundary)
      */
      virtual size_t from_peer(std::span<const uint8_t> data) = 0;

      /**
      * Inject plaintext intended for counterparty
      * Throws an exception if is_active() is false
      */
      virtual void to_peer(std::span<const uint8_t> data) = 0;

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      virtual void send_alert(const Alert& alert) = 0;

      /**
      * Send a warning alert
      */
      void send_warning_alert(Alert::Type type) { send_alert(Alert(type, false)); }

      /**
      * Send a fatal alert
      */
      void send_fatal_alert(Alert::Type type) { send_alert(Alert(type, true)); }

      /**
      * Send a close notification alert
      */
      void close() { send_warning_alert(Alert::CloseNotify); }

      /**
      * @return true iff the TLS handshake has finished successfully
      */
      virtual bool is_handshake_complete() const = 0;

      /**
      * @return true iff the connection is active for sending application data
      */
      virtual bool is_active() const = 0;

      /**
      * @return true iff the connection has been definitely closed
      */
      virtual bool is_closed() const = 0;

      /**
      * @return true iff the connection is active for sending application data
      */
      virtual bool is_closed_for_reading() const = 0;

      /**
      * @return true iff the connection has been definitely closed
      */
      virtual bool is_closed_for_writing() const = 0;

      /**
      * @return certificate chain of the peer (may be empty)
      */
      virtual std::vector<X509_Certificate> peer_cert_chain() const = 0;

      /**
      * @return raw public key of the peer (may be nullptr)
      */
      virtual std::shared_ptr<const Public_Key> peer_raw_public_key() const = 0;

      /**
       * @return identity of the PSK used for this connection
       *         or std::nullopt if no PSK was used.
       */
      virtual std::optional<std::string> external_psk_identity() const = 0;

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      virtual SymmetricKey key_material_export(std::string_view label,
                                               std::string_view context,
                                               size_t length) const = 0;

      /**
      * Attempt to renegotiate the session
      * @param force_full_renegotiation if true, require a full renegotiation,
      * otherwise allow session resumption
      */
      virtual void renegotiate(bool force_full_renegotiation = false) = 0;

      /**
      * @return true if this channel can issue TLS 1.3 style session tickets.
      */
      virtual bool new_session_ticket_supported() const { return false; }

      /**
      * Send @p tickets new session tickets to the peer. This is only supported
      * on TLS 1.3 servers.
      *
      * If the server's Session_Manager does not accept the generated Session
      * objects, the server implementation won't be able to send new tickets.
      * Additionally, anything but TLS 1.3 servers will return 0 (because they
      * don't support sending such session tickets).
      *
      * @returns the number of session tickets successfully sent to the client
      */
      virtual size_t send_new_session_tickets(const size_t /* tickets */) { return 0; }

      /**
      * Attempt to update the session's traffic key material
      * Note that this is possible with a TLS 1.3 channel, only.
      *
      * @param request_peer_update if true, require a reciprocal key update
      */
      virtual void update_traffic_keys(bool request_peer_update = false) = 0;

      /**
      * @return true iff the counterparty supports the secure
      * renegotiation extensions.
      */
      virtual bool secure_renegotiation_supported() const = 0;

      /**
      * Perform a handshake timeout check. This does nothing unless
      * this is a DTLS channel with a pending handshake state, in
      * which case we check for timeout and potentially retransmit
      * handshake packets.
      */
      virtual bool timeout_check() = 0;

      /**
      * Return the protocol notification set for this connection, if any (ALPN).
      * This value is not tied to the session and a later renegotiation of the
      * same session can choose a new protocol.
      */
      virtual std::string application_protocol() const = 0;

   protected:
      /**
       * This struct collect all information required to perform a downgrade from TLS 1.3 to TLS 1.2.
       *
       * The downgrade process is (currently) triggered when a TLS 1.3 client receives a downgrade request
       * in the server hello message (@sa `Client_Impl_13::handle(Server_Hello_12)`). As a result,
       * `Client::received_data` should detect this condition and replace its `Channel_Impl_13` member by a
       * `Channel_Impl_12`.
       *
       * Note that the downgrade process for the server implementation will likely differ.
       */
      struct Downgrade_Information {
            /// The client hello message including the handshake header bytes as transferred to the peer.
            std::vector<uint8_t> client_hello_message;

            /// The full data transcript received from the peer. This will contain the server hello message that forced us to downgrade.
            std::vector<uint8_t> peer_transcript;

            /// The TLS 1.2 session information found by a TLS 1.3 client that
            /// caused it to initiate a downgrade before even sending a client hello.
            std::optional<Session_with_Handle> tls12_session;

            Server_Information server_info;
            std::vector<std::string> next_protocols;
            size_t io_buffer_size;

            std::shared_ptr<Callbacks> callbacks;
            std::shared_ptr<Session_Manager> session_manager;
            std::shared_ptr<Credentials_Manager> creds;
            std::shared_ptr<RandomNumberGenerator> rng;
            std::shared_ptr<const Policy> policy;

            bool received_tls_13_error_alert;
            bool will_downgrade;
      };

      std::unique_ptr<Downgrade_Information> m_downgrade_info;

      void preserve_peer_transcript(std::span<const uint8_t> input) {
         BOTAN_STATE_CHECK(m_downgrade_info);
         m_downgrade_info->peer_transcript.insert(m_downgrade_info->peer_transcript.end(), input.begin(), input.end());
      }

      void preserve_client_hello(std::span<const uint8_t> msg) {
         BOTAN_STATE_CHECK(m_downgrade_info);
         m_downgrade_info->client_hello_message.assign(msg.begin(), msg.end());
      }

      friend class Client;
      friend class Server;

      void set_io_buffer_size(size_t io_buf_sz) {
         BOTAN_STATE_CHECK(m_downgrade_info);
         m_downgrade_info->io_buffer_size = io_buf_sz;
      }

      /**
       * Implementations use this to signal that the peer indicated a protocol
       * version downgrade. After calling `request_downgrade()` no further
       * state changes must be perfomed by the implementation. Particularly, no
       * further handshake messages must be emitted. Instead, they must yield
       * control flow back to the underlying Channel implementation to perform
       * the protocol version downgrade.
       */
      void request_downgrade() {
         BOTAN_STATE_CHECK(m_downgrade_info && !m_downgrade_info->will_downgrade);
         m_downgrade_info->will_downgrade = true;
      }

      void request_downgrade_for_resumption(Session_with_Handle session) {
         BOTAN_STATE_CHECK(m_downgrade_info && m_downgrade_info->client_hello_message.empty() &&
                           m_downgrade_info->peer_transcript.empty() && !m_downgrade_info->tls12_session.has_value());
         BOTAN_ASSERT_NOMSG(session.session.version().is_pre_tls_13());
         m_downgrade_info->tls12_session = std::move(session);
         request_downgrade();
      }

   public:
      /**
       * Indicates whether a downgrade to TLS 1.2 or lower is in progress
       *
       * @sa Downgrade_Information
       */
      bool is_downgrading() const { return m_downgrade_info && m_downgrade_info->will_downgrade; }

      /**
       * @sa Downgrade_Information
       */
      std::unique_ptr<Downgrade_Information> extract_downgrade_info() { return std::exchange(m_downgrade_info, {}); }

      bool expects_downgrade() const { return m_downgrade_info != nullptr; }
};

}  // namespace TLS

}  // namespace Botan

#endif
