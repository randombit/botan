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
#include <botan/tls_version.h>
#include <botan/tls_magic.h>

#include <vector>
#include <memory>

namespace Botan {

class Credentials_Manager;
class X509_Certificate;

namespace TLS {

class Channel_Impl
   {
   public:
      virtual ~Channel_Impl() = default;

      /**
      * Inject TLS traffic received from counterparty
      * @return a hint as the how many more bytes we need to q the
      *         current record (this may be 0 if on a record boundary)
      */
      virtual size_t received_data(const uint8_t buf[], size_t buf_size) = 0;

      /**
      * Inject plaintext intended for counterparty
      * Throws an exception if is_active() is false
      */
      virtual void send(const uint8_t buf[], size_t buf_size) = 0;

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
      void close() { send_warning_alert(Alert::CLOSE_NOTIFY); }

      /**
      * @return true iff the connection is active for sending application data
      */
      virtual bool is_active() const = 0;

      /**
      * @return true iff the connection has been definitely closed
      */
      virtual bool is_closed() const = 0;

      /**
      * @return certificate chain of the peer (may be empty)
      */
      virtual std::vector<X509_Certificate> peer_cert_chain() const = 0;

      /**
      * Key material export (RFC 5705)
      * @param label a disambiguating label string
      * @param context a per-association context value
      * @param length the length of the desired key in bytes
      * @return key of length bytes
      */
      virtual SymmetricKey key_material_export(const std::string& label,
                                       const std::string& context,
                                       size_t length) const = 0;

      /**
      * Attempt to renegotiate the session
      * @param force_full_renegotiation if true, require a full renegotiation,
      * otherwise allow session resumption
      */
      virtual void renegotiate(bool force_full_renegotiation = false) = 0;

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
      struct Downgrade_Information
         {
         /// The client hello message including the handshake header bytes as transferred to the peer.
         std::vector<uint8_t> client_hello_message;

         /// The full data transcript received from the peer. This will contain the server hello message that forced us to downgrade.
         std::vector<uint8_t> peer_transcript;

         Server_Information server_info;

         Callbacks& callbacks;
         Session_Manager& session_manager;
         Credentials_Manager& creds;
         RandomNumberGenerator& rng;
         const Policy& policy;

         bool received_tls_13_error_alert;
         bool will_downgrade;
         };

      std::unique_ptr<Downgrade_Information> m_downgrade_info;

      void preserve_peer_transcript(const uint8_t input[], size_t input_size)
         {
         BOTAN_STATE_CHECK(m_downgrade_info);
         m_downgrade_info->peer_transcript.insert(m_downgrade_info->peer_transcript.end(),
                                                  input, input+input_size);
         }

      void preserve_client_hello(const std::vector<uint8_t>& msg)
         {
         BOTAN_STATE_CHECK(m_downgrade_info);
         m_downgrade_info->client_hello_message = msg;
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

}

}

#endif
