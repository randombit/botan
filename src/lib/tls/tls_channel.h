/*
* TLS Channel
* (C) 2011,2012,2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CHANNEL_H_
#define BOTAN_TLS_CHANNEL_H_

#include <botan/tls_session.h>
#include <botan/tls_alert.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/x509cert.h>

#include <vector>
#include <string>
#include <string_view>
#include <span>

namespace Botan::TLS {

/**
* Generic interface for TLS endpoint
*/
class BOTAN_PUBLIC_API(2,0) Channel
   {
   public:
      static constexpr size_t IO_BUF_DEFAULT_SIZE = 10*1024;

      virtual ~Channel() = default;

   protected:
      virtual size_t from_peer(std::span<const uint8_t> data) = 0;
      virtual void to_peer(std::span<const uint8_t> data) = 0;

   public:
      /**
      * Inject TLS traffic received from counterparty
      *
      * This function is used to provide data sent by the counterparty (eg data
      * that you read off the socket layer). Depending on the current protocol
      * state and the amount of data provided this may result in one or more
      * callbacks in the TLS::Callbacks object provided to the constructor being
      * called.
      *
      * The return value of received_data() specifies how many more bytes of
      * input are needed to make any progress, unless the end of the data fell
      * exactly on a message boundary, in which case it will return 0 instead.
      *
      * @param data  a buffer holding data received from the peer
      * @return a hint as to how many more bytes we need to process the current
      *         record (this may be 0 if on a record boundary)
      */
      size_t received_data(std::span<const uint8_t> data)
         { return this->from_peer(data); }
      size_t received_data(const uint8_t buf[], size_t buf_size)
         { return this->from_peer(std::span(buf, buf_size)); }

      /**
      * Inject plaintext intended for counterparty
      *
      * Create one or more new TLS application records containing the provided
      * @p data and send them. This will eventually result in at least one call
      * to TLS::Callbacks::tls_emit_data().
      *
      * If the current TLS connection state is unable to transmit new
      * application records (for example because a handshake has not yet
      * completed or the connection has already ended due to an error) an
      * exception will be thrown.
      *
      * @param data  a buffer containing data to be transmitted to the peer
      */
      void send(std::span<const uint8_t> data)
         { this->to_peer(data); }
      void send(const uint8_t buf[], size_t buf_size)
         { this->to_peer(std::span(buf, buf_size)); }
      void send(std::string_view val)
         { this->send(std::span(cast_char_ptr_to_uint8(val.data()), val.size())); }

      /**
      * Send a TLS alert message.
      *
      * If the alert is fatal, the internal state (keys, etc) will be reset.
      *
      * @param alert the Alert to send
      */
      virtual void send_alert(const Alert& alert) = 0;

      /**
      * Send a warning alert
      */
      virtual void send_warning_alert(Alert::Type type) = 0;

      /**
      * Send a fatal alert
      */
      virtual void send_fatal_alert(Alert::Type type) = 0;

      /**
      * Send a close notification alert
      *
      * No more data can be sent after calling this on the channel. Therefore,
      * is_active() will return `false` and is_closed_for_writing() will return
      * `true`.
      */
      virtual void close() = 0;

      /**
      * Returns true if and only if a handshake has been completed on this
      * connection and the connection has not been subsequently closed.
      *
      * @return true iff the connection is active for sending application data
      */
      virtual bool is_active() const = 0;

      /**
      * Returns true if and only if either a close notification or a fatal alert
      * message have been either sent or received.
      *
      * @note For TLS 1.3 a connection is closed only after both peers have
      *       signaled a "close_notify". While TLS 1.2 automatically responded
      *       in suit once the peer had sent "close_notify", TLS 1.3 allows to
      *       continue transmitting data even if the peer closed their writing
      *       end.
      *
      * @return true iff the connection has been definitely closed
      */
      virtual bool is_closed() const = 0;

      /**
      * @return true iff the peer closed their channel
      *         (i.e. no more incoming data expected)
      */
      virtual bool is_closed_for_reading() const = 0;

      /**
      * @return true iff we closed our channel
      *         (i.e. no more outgoing data allowed)
      */
      virtual bool is_closed_for_writing() const = 0;

      /**
      * Returns the certificate chain of the counterparty.
      *
      * When acting as a client, this value will be non-empty. Acting as a
      * server, this value will ordinarily be empty, unless the server requested
      * a certificate and the client responded with one.
      *
      * @return certificate chain of the peer (may be empty)
      */
      virtual std::vector<X509_Certificate> peer_cert_chain() const = 0;

      /**
      * Key material export (RFC 5705 & RFC 8446 7.5)
      *
      * Returns an exported key of @p length bytes derived from @p label,
      * @p context, and the session's master secret and client and server random
      * values. This key will be unique to this connection, and as long as the
      * session master secret remains secure an attacker should not be able to
      * guess the key.
      *
      * Per :rfc:`5705`, @p label should begin with "EXPERIMENTAL" unless the
      * label has been standardized in an RFC.
      *
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
      *
      * The counterparty is allowed by the protocol to ignore this request. If
      * successful, TLS::Callbacks::tls_session_established()  will be called
      * again.
      *
      * If @p force_full_renegotiation is `false`, then the client will attempt
      * to simply renew the current session - this will refresh the symmetric
      * keys but will not change the session master secret. Otherwise it will
      * initiate a completely new session.
      *
      * For a server, if @p force_full_renegotiation is `false`, then a session
      * resumption will be allowed if the client attempts it. Otherwise the
      * server will prevent resumption and force the creation of a new session.
      *
      * @note TLS 1.3 does not support renegotiation and this method will throw
      *       an exception. Instead, use update_traffic_keys() to forcefully
      *       renew the session keys. Additionally, TLS 1.3 provides a
      *       post-handshake client authentication mechanism (RFC 8446 4.6.2).
      *       The latter is not yet implemented in Botan.
      *
      * @param force_full_renegotiation if true, require a full renegotiation,
      *                                 otherwise allow session resumption
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
      * Perform a handshake timeout check.
      *
      * This function does nothing unless the channel represents a DTLS
      * connection and a handshake is actively in progress. In this case it will
      * check the current timeout state and potentially initiate retransmission
      * of handshake packets.
      *
      * @returns true if a timeout condition occurred
      */
      virtual bool timeout_check() = 0;

      virtual std::string application_protocol() const = 0;
   };
}

#endif
