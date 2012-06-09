/*
* TLS Channel
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CHANNEL_H__
#define BOTAN_TLS_CHANNEL_H__

#include <botan/tls_policy.h>
#include <botan/tls_record.h>
#include <botan/tls_session.h>
#include <botan/tls_alert.h>
#include <botan/tls_session_manager.h>
#include <botan/x509cert.h>
#include <vector>

namespace Botan {

namespace TLS {

/**
* Generic interface for TLS endpoint
*/
class BOTAN_DLL Channel
   {
   public:
      /**
      * Inject TLS traffic received from counterparty
      * @return a hint as the how many more bytes we need to process the
      *         current record (this may be 0 if on a record boundary)
      */
      virtual size_t received_data(const byte buf[], size_t buf_size);

      /**
      * Inject plaintext intended for counterparty
      */
      virtual void send(const byte buf[], size_t buf_size);

      /**
      * Send a close notification alert
      */
      void close() { send_alert(Alert(Alert::CLOSE_NOTIFY)); }

      /**
      * @return true iff the connection is active for sending application data
      */
      bool is_active() const { return m_handshake_completed && !is_closed(); }

      /**
      * @return true iff the connection has been definitely closed
      */
      bool is_closed() const { return m_connection_closed; }

      /**
      * Attempt to renegotiate the session
      * @param force_full_renegotiation if true, require a full renegotiation,
      *                                 otherwise allow session resumption
      */
      virtual void renegotiate(bool force_full_renegotiation) = 0;

      /**
      * Attempt to send a heartbeat message (if negotiated with counterparty)
      * @param payload will be echoed back
      * @param countents_size size of payload in bytes
      */
      void heartbeat(const byte payload[], size_t payload_size);

      /**
      * Attempt to send a heartbeat message (if negotiated with counterparty)
      */
      void heartbeat() { heartbeat(nullptr, 0); }

      /**
      * @return certificate chain of the peer (may be empty)
      */
      std::vector<X509_Certificate> peer_cert_chain() const { return m_peer_certs; }

      Channel(std::function<void (const byte[], size_t)> socket_output_fn,
              std::function<void (const byte[], size_t, Alert)> proc_fn,
              std::function<bool (const Session&)> handshake_complete,
              Session_Manager& session_manager);

      virtual ~Channel();
   protected:

      /**
      * Send a TLS alert message. If the alert is fatal, the
      * internal state (keys, etc) will be reset
      * @param level is warning or fatal
      * @param type is the type of alert
      */
      void send_alert(const Alert& alert);

      virtual void read_handshake(byte rec_type,
                                  const std::vector<byte>& rec_buf);

      virtual void process_handshake_msg(Handshake_Type type,
                                         const std::vector<byte>& contents) = 0;

      virtual void alert_notify(const Alert& alert) = 0;

      class Secure_Renegotiation_State
         {
         public:
            Secure_Renegotiation_State() : m_initial_handshake(true),
                                           m_secure_renegotiation(false)
               {}

            void update(class Client_Hello* client_hello);
            void update(class Server_Hello* server_hello);

            void update(class Finished* client_finished,
                        class Finished* server_finished);

            const std::vector<byte>& for_client_hello() const
               { return m_client_verify; }

            std::vector<byte> for_server_hello() const
               {
               std::vector<byte> buf = m_client_verify;
               buf += m_server_verify;
               return buf;
               }

            bool supported() const
               { return m_secure_renegotiation; }

            bool initial_handshake() const { return m_initial_handshake; }
         private:
            bool m_initial_handshake;
            bool m_secure_renegotiation;
            std::vector<byte> m_client_verify, m_server_verify;
         };

      std::function<void (const byte[], size_t, Alert)> m_proc_fn;
      std::function<bool (const Session&)> m_handshake_fn;

      class Handshake_State* m_state;

      Session_Manager& m_session_manager;
      Record_Writer m_writer;
      Record_Reader m_reader;

      std::vector<X509_Certificate> m_peer_certs;

      Secure_Renegotiation_State m_secure_renegotiation;

      std::vector<byte> m_active_session;
      bool m_handshake_completed;
      bool m_connection_closed;
      bool m_peer_supports_heartbeats;
      bool m_heartbeat_sending_allowed;
   };

}

}

#endif
