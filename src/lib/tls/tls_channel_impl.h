/*
* TLS Channel
* (C) 2011,2012,2014,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
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

class X509_Certificate;

namespace TLS {

class Handshake_State;
class Handshake_IO;

class Channel_Impl
   {
   public:
      virtual ~Channel_Impl() = default;


      virtual Handshake_State& create_handshake_state(Protocol_Version version) = 0;

      /**
      * Inject TLS traffic received from counterparty
      * @return a hint as the how many more bytes we need to process the
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
      virtual void close() = 0;


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

      virtual void process_handshake_msg(const Handshake_State* active_state,
                                         Handshake_State& pending_state,
                                         Handshake_Type type,
                                         const std::vector<uint8_t>& contents,
                                         bool epoch0_restart) = 0;

      virtual void initiate_handshake(Handshake_State& state,
                                      bool force_full_renegotiation) = 0;

      virtual std::vector<X509_Certificate>
         get_peer_cert_chain(const Handshake_State& state) const = 0;

      virtual std::unique_ptr<Handshake_State>
         new_handshake_state(std::unique_ptr<class Handshake_IO> io) = 0;
   };

}

}

#endif
