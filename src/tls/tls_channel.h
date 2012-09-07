/*
* TLS Channel
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_CHANNEL_H__
#define BOTAN_TLS_CHANNEL_H__

#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/tls_alert.h>
#include <botan/tls_session_manager.h>
#include <botan/x509cert.h>
#include <vector>
#include <string>
#include <memory>

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
      void send(const byte buf[], size_t buf_size);

      /**
      * Inject plaintext intended for counterparty
      */
      void send(const std::string& string);

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
      void renegotiate(bool force_full_renegotiation = false);

      /**
      * Attempt to send a heartbeat message (if negotiated with counterparty)
      * @param payload will be echoed back
      * @param payload_size size of payload in bytes
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
              Session_Manager& session_manager,
              RandomNumberGenerator& rng);

      Channel(const Channel&) = delete;

      Channel& operator=(const Channel&) = delete;

      virtual ~Channel();
   protected:

      virtual void process_handshake_msg(class Handshake_State& state,
                                         Handshake_Type type,
                                         const std::vector<byte>& contents) = 0;

      virtual void initiate_handshake(class Handshake_State& state,
                                      bool force_full_renegotiation) = 0;

      virtual class Handshake_State* new_handshake_state() = 0;

      class Handshake_State& create_handshake_state();

      /**
      * Send a TLS alert message. If the alert is fatal, the internal
      * state (keys, etc) will be reset.
      * @param alert the Alert to send
      */
      void send_alert(const Alert& alert);

      void activate_session(const std::vector<byte>& session_id);

      void heartbeat_support(bool peer_supports, bool allowed_to_send);

      void set_protocol_version(Protocol_Version version);

      Protocol_Version current_protocol_version() const
         { return m_current_version; }

      void set_maximum_fragment_size(size_t maximum);

      void change_cipher_spec_reader(Connection_Side side);

      void change_cipher_spec_writer(Connection_Side side);

      void send_record(byte record_type, const std::vector<byte>& record);

      class Secure_Renegotiation_State
         {
         public:
            void update(const class Client_Hello* client_hello);
            void update(const class Server_Hello* server_hello);

            void update(const class Finished* client_finished,
                        const class Finished* server_finished);

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
            bool m_initial_handshake = true;
            bool m_secure_renegotiation = false;
            std::vector<byte> m_client_verify, m_server_verify;
         };

      std::function<bool (const Session&)> m_handshake_fn;

      RandomNumberGenerator& m_rng;
      Session_Manager& m_session_manager;

      std::vector<X509_Certificate> m_peer_certs;

      Secure_Renegotiation_State m_secure_renegotiation;

   private:
      void send_record(byte type, const byte input[], size_t length);

      void write_record(byte type, const byte input[], size_t length);

      /* callbacks */
      std::function<void (const byte[], size_t, Alert)> m_proc_fn;
      std::function<void (const byte[], size_t)> m_output_fn;

      /* writing cipher state */
      std::vector<byte> m_writebuf;
      std::unique_ptr<class Connection_Cipher_State> m_write_cipherstate;
      u64bit m_write_seq_no = 0;

      /* reading cipher state */
      std::vector<byte> m_readbuf;
      size_t m_readbuf_pos = 0;
      std::unique_ptr<class Connection_Cipher_State> m_read_cipherstate;
      u64bit m_read_seq_no = 0;

      /* connection parameters */
      std::unique_ptr<class Handshake_State> m_state;

      Protocol_Version m_current_version;
      size_t m_max_fragment = MAX_PLAINTEXT_SIZE;

      bool m_peer_supports_heartbeats = false;
      bool m_heartbeat_sending_allowed = false;

      bool m_connection_closed = false;
      bool m_handshake_completed = false;
      std::vector<byte> m_active_session;
   };

}

}

#endif
